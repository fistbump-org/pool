import Foundation
import Logging

/// PPLNS share accounting with database-backed block tracking.
///
/// Maintains a sliding window of recent shares for PPLNS. When a block is found,
/// the share window is snapshotted to the database. Rewards are credited only
/// after blocks mature (handled by MaturityChecker).
public final class ShareLog: @unchecked Sendable {
    private let lock = NSLock()

    /// Pool fee fraction (e.g. 0.01 = 1%).
    private let poolFee: Double

    /// Pool fee as a percentage for API display.
    public var feePercent: Double { poolFee * 100.0 }

    /// PPLNS window size in total difficulty-weighted shares.
    private var windowSize: Double

    /// Ring of recent shares (in-memory only, not persisted).
    private var shares: [Share] = []

    /// Database for persistent storage.
    private let db: PoolDatabase

    private let logger: Logger

    public init(poolFee: Double, windowMultiple: Double, db: PoolDatabase, logger: Logger) {
        self.poolFee = poolFee
        self.windowSize = 1000.0 * windowMultiple
        self.db = db
        self.logger = logger
    }

    /// Update the PPLNS window size based on current network difficulty.
    public func updateWindowSize(networkDifficulty: Double, windowMultiple: Double) {
        lock.lock()
        defer { lock.unlock() }
        windowSize = networkDifficulty * windowMultiple
    }

    /// Record a share from a miner (keyed by payout address).
    public func addShare(address: String, difficulty: Double) {
        let share = Share(address: address, difficulty: difficulty, time: Date())
        lock.lock()
        shares.append(share)
        trimWindow()
        lock.unlock()
    }

    /// Record a found block: snapshot PPLNS shares and save to DB.
    /// Rewards are NOT credited here — MaturityChecker credits them when mature.
    public func recordBlock(height: Int, hash: String, blockReward: Int64) {
        lock.lock()
        defer { lock.unlock() }

        // Already recorded (e.g. duplicate submission)?
        guard !db.isBlockRecorded(height: height) else { return }

        // Save block as immature
        db.insertBlock(height: height, hash: hash, reward: blockReward, foundAt: Date())

        // Snapshot current PPLNS window
        if shares.isEmpty {
            logger.warning("Block \(height) found but PPLNS window is empty — reward will be uncredited", source: "ShareLog")
            return
        }

        let netReward = Int64(Double(blockReward) * (1.0 - poolFee))
        let totalDiff = shares.reduce(0.0) { $0 + $1.difficulty }
        guard totalDiff > 0 else { return }

        var snapshot: [(address: String, difficulty: Double, fraction: Double, credit: Int64)] = []
        // Aggregate by address
        var addrDiff: [String: Double] = [:]
        for share in shares {
            addrDiff[share.address, default: 0] += share.difficulty
        }
        for (addr, diff) in addrDiff {
            let fraction = diff / totalDiff
            let credit = Int64(Double(netReward) * fraction)
            if credit > 0 {
                snapshot.append((addr, diff, fraction, credit))
            }
        }

        db.insertBlockShares(blockHeight: height, shares: snapshot)
        logger.info("Block \(height) recorded (immature) — \(snapshot.count) miners in PPLNS snapshot", source: "ShareLog")
    }

    /// Record a completed payout.
    public func recordPayout(address: String, amount: Int64, txid: String) {
        db.debitBalance(address: address, amount: amount)
        db.insertPayout(txid: txid, address: address, amount: amount)
    }

    /// Get addresses with balances above the given threshold (in bumps).
    public func pendingPayouts(minBalance: Int64) -> [String: Int64] {
        let pending = db.getPendingPayouts(minBalance: minBalance)
        var result: [String: Int64] = [:]
        for (addr, amount) in pending {
            result[addr] = amount
        }
        return result
    }

    // MARK: - Stats

    public var stats: ShareStats {
        lock.lock()
        defer { lock.unlock() }
        let totalDiff = shares.reduce(0.0) { $0 + $1.difficulty }
        var addressShares: [String: Int] = [:]
        for share in shares {
            addressShares[share.address, default: 0] += 1
        }
        return ShareStats(
            windowShares: shares.count,
            windowDifficulty: totalDiff,
            windowSize: windowSize,
            addressShareCounts: addressShares
        )
    }

    public var foundBlocks: [PoolDatabase.BlockRecord] {
        db.getAllBlocks()
    }

    public var blockCount: Int {
        db.getBlockCount()
    }

    public var minerBalances: [(address: String, balance: Int64, totalEarned: Int64, totalPaid: Int64)] {
        db.getAllBalances()
    }

    public var recentPayouts: [PoolDatabase.PayoutRecord] {
        db.getRecentPayouts()
    }

    // MARK: - Private

    private func trimWindow() {
        var totalDiff = shares.reduce(0.0) { $0 + $1.difficulty }
        while totalDiff > windowSize && shares.count > 1 {
            totalDiff -= shares.first!.difficulty
            shares.removeFirst()
        }
    }
}

// MARK: - Types

struct Share {
    let address: String
    let difficulty: Double
    let time: Date
}

public struct ShareStats: Sendable {
    public let windowShares: Int
    public let windowDifficulty: Double
    public let windowSize: Double
    public let addressShareCounts: [String: Int]
}
