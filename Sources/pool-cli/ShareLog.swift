import Foundation

/// PPLNS share accounting, balance tracking, and payout management.
///
/// Maintains a sliding window of recent shares. When a block is found,
/// the reward is attributed proportionally to shares in the window and
/// credited to each miner's balance. Balances persist to disk.
public final class ShareLog: @unchecked Sendable {
    private let lock = NSLock()

    /// Pool fee fraction (e.g. 0.01 = 1%).
    private let poolFee: Double

    /// Pool fee as a percentage for API display.
    public var feePercent: Double { poolFee * 100.0 }

    /// PPLNS window size in total difficulty-weighted shares.
    private var windowSize: Double

    /// Ring of recent shares.
    private var shares: [Share] = []

    /// Blocks found by the pool.
    private var blocks: [FoundBlock] = []

    /// Accumulated unpaid balances per payout address (in bumps).
    private var balances: [String: Int64] = [:]

    /// Total paid out per address (in bumps).
    private var totalPaid: [String: Int64] = [:]

    /// Payout history.
    private var payouts: [PayoutRecord] = []

    /// Path to persist balances.
    private let dataPath: String?

    public init(poolFee: Double, windowMultiple: Double, dataPath: String? = nil) {
        self.poolFee = poolFee
        self.windowSize = 1000.0 * windowMultiple
        self.dataPath = dataPath
        if let path = dataPath {
            loadState(from: path)
        }
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

    /// Record a found block: calculate PPLNS payouts and credit balances.
    /// `blockReward` is in bumps (1 FBC = 1,000,000 bumps).
    public func recordBlock(height: Int, hash: String, blockReward: Int64) {
        lock.lock()
        defer { lock.unlock() }

        let block = FoundBlock(
            height: height,
            hash: hash,
            time: Date(),
            totalShares: shares.count,
            totalDifficulty: shares.reduce(0) { $0 + $1.difficulty },
            reward: blockReward
        )
        blocks.append(block)
        if blocks.count > 1000 {
            blocks.removeFirst(blocks.count - 1000)
        }

        // PPLNS payout calculation
        guard !shares.isEmpty else { return }
        let netReward = Int64(Double(blockReward) * (1.0 - poolFee))
        let totalDiff = shares.reduce(0.0) { $0 + $1.difficulty }
        guard totalDiff > 0 else { return }

        for share in shares {
            let fraction = share.difficulty / totalDiff
            let amount = Int64(Double(netReward) * fraction)
            if amount > 0 {
                balances[share.address, default: 0] += amount
            }
        }

        saveState()
    }

    /// Record a completed payout.
    public func recordPayout(address: String, amount: Int64, txid: String) {
        lock.lock()
        defer { lock.unlock() }

        balances[address, default: 0] -= amount
        if balances[address, default: 0] <= 0 {
            balances.removeValue(forKey: address)
        }

        totalPaid[address, default: 0] += amount

        payouts.append(PayoutRecord(
            address: address,
            amount: amount,
            txid: txid,
            time: Date()
        ))
        if payouts.count > 10000 {
            payouts.removeFirst(payouts.count - 10000)
        }

        saveState()
    }

    /// Get addresses with balances above the given threshold (in bumps).
    public func pendingPayouts(minBalance: Int64) -> [String: Int64] {
        lock.lock()
        defer { lock.unlock() }
        return balances.filter { $0.value >= minBalance }
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

    public var foundBlocks: [FoundBlock] {
        lock.lock()
        defer { lock.unlock() }
        return blocks
    }

    public var minerBalances: [String: Int64] {
        lock.lock()
        defer { lock.unlock() }
        return balances
    }

    public var recentPayouts: [PayoutRecord] {
        lock.lock()
        defer { lock.unlock() }
        return Array(payouts.suffix(100))
    }

    // MARK: - Private

    private func trimWindow() {
        var totalDiff = shares.reduce(0.0) { $0 + $1.difficulty }
        while totalDiff > windowSize && shares.count > 1 {
            totalDiff -= shares.first!.difficulty
            shares.removeFirst()
        }
    }

    // MARK: - Persistence

    /// Atomic save: write to .tmp, fsync, rename over the real file.
    private func saveState() {
        guard let path = dataPath else { return }
        let state: [String: Any] = [
            "balances": balances.mapValues { NSNumber(value: $0) },
            "total_paid": totalPaid.mapValues { NSNumber(value: $0) },
            "blocks_found": blocks.count,
            "payouts": payouts.suffix(1000).map { p -> [String: Any] in
                ["address": p.address, "amount": p.amount, "txid": p.txid,
                 "time": Int(p.time.timeIntervalSince1970)]
            },
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: state) else { return }

        let tmpPath = path + ".tmp"
        let backupPath = path + ".bak"
        do {
            try data.write(to: URL(fileURLWithPath: tmpPath), options: .atomic)
            // Keep one backup of the previous state
            let fm = FileManager.default
            if fm.fileExists(atPath: path) {
                try? fm.removeItem(atPath: backupPath)
                try? fm.copyItem(atPath: path, toPath: backupPath)
            }
            try fm.moveItem(atPath: tmpPath, toPath: path)
        } catch {
            // Atomic write failed — leave previous state intact
            try? FileManager.default.removeItem(atPath: tmpPath)
        }
    }

    private func loadState(from path: String) {
        // Try primary, fall back to backup
        let data: Data
        if let d = try? Data(contentsOf: URL(fileURLWithPath: path)) {
            data = d
        } else if let d = try? Data(contentsOf: URL(fileURLWithPath: path + ".bak")) {
            data = d
        } else {
            return
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }

        if let bals = json["balances"] as? [String: NSNumber] {
            for (addr, amount) in bals {
                balances[addr] = amount.int64Value
            }
        }
        if let paid = json["total_paid"] as? [String: NSNumber] {
            for (addr, amount) in paid {
                totalPaid[addr] = amount.int64Value
            }
        }
        if let payoutList = json["payouts"] as? [[String: Any]] {
            for p in payoutList {
                guard let addr = p["address"] as? String,
                      let amount = (p["amount"] as? NSNumber)?.int64Value,
                      let txid = p["txid"] as? String,
                      let time = p["time"] as? Int else { continue }
                payouts.append(PayoutRecord(
                    address: addr, amount: amount, txid: txid,
                    time: Date(timeIntervalSince1970: Double(time))
                ))
            }
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

public struct FoundBlock: Sendable {
    public let height: Int
    public let hash: String
    public let time: Date
    public let totalShares: Int
    public let totalDifficulty: Double
    public let reward: Int64
}

public struct PayoutRecord: Sendable {
    public let address: String
    public let amount: Int64
    public let txid: String
    public let time: Date
}
