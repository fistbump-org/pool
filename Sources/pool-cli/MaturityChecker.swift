import Foundation
import Logging

/// Periodically checks immature blocks for maturity and credits PPLNS rewards.
public final class MaturityChecker: @unchecked Sendable {
    private let rpc: NodeRPC
    private let db: PoolDatabase
    private let coinbaseMaturity: Int
    private let logger: Logger
    private var task: Task<Void, Never>?

    public init(rpc: NodeRPC, db: PoolDatabase, coinbaseMaturity: Int, logger: Logger) {
        self.rpc = rpc
        self.db = db
        self.coinbaseMaturity = coinbaseMaturity
        self.logger = logger
    }

    public func start() {
        task = Task { [self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000) // 30s
                await checkMaturity()
            }
        }
    }

    public func stop() {
        task?.cancel()
        task = nil
    }

    private func checkMaturity() async {
        let immature = db.getImmatureBlocks()
        guard !immature.isEmpty else { return }

        for block in immature {
            do {
                let (hash, confirmations) = try await rpc.getBlock(height: block.height)

                db.updateBlockConfirmations(height: block.height, confirmations: confirmations)

                // Reorg check: if the hash changed, the block was orphaned
                if hash != block.hash {
                    db.markBlockOrphan(height: block.height)
                    logger.warning("Block \(block.height) orphaned (hash mismatch)", source: "Maturity")
                    continue
                }

                if confirmations >= coinbaseMaturity {
                    db.markBlockMature(height: block.height)

                    // Credit PPLNS rewards if not already credited
                    if !block.credited {
                        let shares = db.getBlockShares(blockHeight: block.height)
                        if shares.isEmpty {
                            logger.warning("Block \(block.height) mature but no share snapshot — reward uncredited", source: "Maturity")
                        } else {
                            for share in shares {
                                db.creditBalance(address: share.address, amount: share.credit)
                            }
                            db.markBlockCredited(height: block.height)
                            logger.info("Block \(block.height) matured — credited \(shares.count) miners", source: "Maturity")
                        }
                    }
                }
            } catch {
                logger.error("Maturity check failed for block \(block.height): \(error)", source: "Maturity")
            }
        }
    }
}
