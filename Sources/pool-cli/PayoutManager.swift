import Foundation
import Logging

/// Periodically checks miner balances and sends payouts via fbd wallet RPC.
public final class PayoutManager: @unchecked Sendable {
    private let rpc: NodeRPC
    private let shareLog: ShareLog
    private let walletName: String
    private let minPayout: Int64
    private let interval: TimeInterval
    private let logger: Logger
    private var task: Task<Void, Never>?

    /// Create a payout manager.
    /// - Parameters:
    ///   - rpc: fbd RPC client
    ///   - shareLog: share log with balances
    ///   - walletName: fbd wallet name to send from
    ///   - minPayout: minimum balance to trigger payout (in bumps)
    ///   - interval: how often to check for pending payouts (seconds)
    public init(
        rpc: NodeRPC,
        shareLog: ShareLog,
        walletName: String,
        minPayout: Int64,
        interval: TimeInterval = 300,
        logger: Logger
    ) {
        self.rpc = rpc
        self.shareLog = shareLog
        self.walletName = walletName
        self.minPayout = minPayout
        self.interval = interval
        self.logger = logger
    }

    /// Start the periodic payout loop.
    public func start() {
        task = Task { [self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                await self.processPendingPayouts()
            }
        }
    }

    /// Stop the payout loop.
    public func stop() {
        task?.cancel()
        task = nil
    }

    /// Process all pending payouts above the minimum threshold.
    private func processPendingPayouts() async {
        let pending = shareLog.pendingPayouts(minBalance: minPayout)
        guard !pending.isEmpty else { return }

        // Batch into groups of 50 to avoid oversized transactions
        let sorted = pending.sorted { $0.value > $1.value }
        var batches: [[(address: String, amountBumps: Int64)]] = []
        var current: [(address: String, amountBumps: Int64)] = []

        for (addr, amount) in sorted {
            current.append((addr, amount))
            if current.count >= 50 {
                batches.append(current)
                current = []
            }
        }
        if !current.isEmpty {
            batches.append(current)
        }

        for batch in batches {
            let totalFBC = batch.reduce(0.0) { $0 + Double($1.amountBumps) / 1_000_000.0 }
            let count = batch.count

            logger.info("Sending payout", metadata: [
                "recipients": "\(count)",
                "total_fbc": "\(String(format: "%.6f", totalFBC))",
            ], source: "Payout")

            do {
                let txid = try await rpc.sendPayout(walletName: walletName, payouts: batch)

                logger.info("Payout sent", metadata: [
                    "txid": "\(txid)",
                    "recipients": "\(count)",
                ], source: "Payout")

                // Record each payout
                for (addr, amount) in batch {
                    shareLog.recordPayout(address: addr, amount: amount, txid: txid)
                }
            } catch {
                logger.error("Payout failed: \(error)", source: "Payout")
                // Don't remove from balances — will retry next cycle
            }
        }
    }
}
