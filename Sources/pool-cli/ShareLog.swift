import Foundation

/// PPLNS share accounting and block tracking.
///
/// Maintains a sliding window of recent shares. When a block is found,
/// the reward is attributed proportionally to shares in the window.
public final class ShareLog: @unchecked Sendable {
    private let lock = NSLock()

    /// Pool fee fraction (e.g. 0.01 = 1%).
    private let poolFee: Double

    /// PPLNS window size in total difficulty-weighted shares.
    /// Roughly: expected shares per block * windowMultiple.
    private var windowSize: Double

    /// Ring of recent shares.
    private var shares: [Share] = []

    /// Blocks found by the pool.
    private var blocks: [FoundBlock] = []

    /// Accumulated payouts per username.
    private var balances: [String: Int64] = [:]

    public init(poolFee: Double, windowMultiple: Double) {
        self.poolFee = poolFee
        // Initial window size — recalculated when we know the network difficulty.
        self.windowSize = 1000.0 * windowMultiple
    }

    /// Update the PPLNS window size based on current network difficulty.
    /// Called when a new job arrives so the window tracks the expected shares per block.
    public func updateWindowSize(networkDifficulty: Double, windowMultiple: Double) {
        lock.lock()
        defer { lock.unlock() }
        // Expected difficulty-weighted shares per block ≈ networkDifficulty
        // (since each share contributes its own difficulty to the total).
        windowSize = networkDifficulty * windowMultiple
    }

    /// Record a share from a worker.
    public func addShare(worker: String, difficulty: Double) {
        let share = Share(worker: worker, difficulty: difficulty, time: Date())
        lock.lock()
        shares.append(share)
        trimWindow()
        lock.unlock()
    }

    /// Record a found block and calculate PPLNS payouts.
    public func recordBlock(height: Int, hash: String) {
        lock.lock()
        defer { lock.unlock() }

        let block = FoundBlock(
            height: height,
            hash: hash,
            time: Date(),
            totalShares: shares.count,
            totalDifficulty: shares.reduce(0) { $0 + $1.difficulty }
        )
        blocks.append(block)

        // Keep last 1000 blocks
        if blocks.count > 1000 {
            blocks.removeFirst(blocks.count - 1000)
        }
    }

    /// Calculate PPLNS payouts for a block reward.
    /// Returns (worker -> payout amount) after deducting pool fee.
    public func calculatePayouts(blockReward: Int64) -> [String: Int64] {
        lock.lock()
        let currentShares = shares
        lock.unlock()

        guard !currentShares.isEmpty else { return [:] }

        let netReward = Int64(Double(blockReward) * (1.0 - poolFee))

        // Sum difficulty-weighted shares in the window
        let totalDiff = currentShares.reduce(0.0) { $0 + $1.difficulty }
        guard totalDiff > 0 else { return [:] }

        var payouts: [String: Int64] = [:]
        for share in currentShares {
            let fraction = share.difficulty / totalDiff
            let amount = Int64(Double(netReward) * fraction)
            payouts[share.worker, default: 0] += amount
        }

        return payouts
    }

    /// Get current share window stats.
    public var stats: ShareStats {
        lock.lock()
        defer { lock.unlock() }
        let totalDiff = shares.reduce(0.0) { $0 + $1.difficulty }
        var workerShares: [String: Int] = [:]
        for share in shares {
            workerShares[share.worker, default: 0] += 1
        }
        return ShareStats(
            windowShares: shares.count,
            windowDifficulty: totalDiff,
            windowSize: windowSize,
            workerShareCounts: workerShares
        )
    }

    /// Get blocks found by the pool.
    public var foundBlocks: [FoundBlock] {
        lock.lock()
        defer { lock.unlock() }
        return blocks
    }

    /// Get accumulated balances.
    public var workerBalances: [String: Int64] {
        lock.lock()
        defer { lock.unlock() }
        return balances
    }

    // MARK: - Private

    /// Trim the share window to maintain PPLNS size. Caller must hold lock.
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
    let worker: String
    let difficulty: Double
    let time: Date
}

public struct ShareStats: Sendable {
    public let windowShares: Int
    public let windowDifficulty: Double
    public let windowSize: Double
    public let workerShareCounts: [String: Int]
}

public struct FoundBlock: Sendable {
    public let height: Int
    public let hash: String
    public let time: Date
    public let totalShares: Int
    public let totalDifficulty: Double
}
