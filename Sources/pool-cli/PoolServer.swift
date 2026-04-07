import Base
import Consensus
import Foundation
import Logging

/// Main pool orchestrator — wires together Stratum server, share log, payouts, and API.
public final class PoolServer: Sendable {
    public let config: PoolConfig
    public let logger: Logger

    public init(config: PoolConfig, logger: Logger) {
        self.config = config
        self.logger = logger
    }

    /// Start all pool services and run until cancelled.
    public func run() async throws {
        logger.info("Starting pool", metadata: [
            "network": "\(config.network.rawValue)",
            "address": "\(config.poolAddress)",
            "stratum": "\(config.stratumHost):\(config.effectiveStratumPort)",
            "fee": "\(config.poolFee * 100)%",
            "min_payout": "\(Double(config.minPayout) / 1_000_000.0) FBC",
            "wallet": "\(config.walletName)",
        ], source: "Pool")

        // Create data directory
        let dataDir = NSString(string: config.dataDir).expandingTildeInPath
        try FileManager.default.createDirectory(atPath: dataDir, withIntermediateDirectories: true)

        // Open database
        let dbPath = dataDir + "/pool.db"
        let db = try PoolDatabase(path: dbPath, logger: logger)

        // Migrate from JSON if database is empty and JSON exists
        let jsonPath = dataDir + "/pool-state.json"
        if db.isEmpty() && FileManager.default.fileExists(atPath: jsonPath) {
            logger.info("Migrating from pool-state.json to SQLite...", source: "Pool")
            db.importFromJSON(path: jsonPath)
            let migratedPath = jsonPath + ".migrated"
            try? FileManager.default.moveItem(atPath: jsonPath, toPath: migratedPath)
            logger.info("Migration complete — JSON renamed to .migrated", source: "Pool")
        }

        let rpc = NodeRPC(url: config.nodeURL, apiKey: config.nodeAPIKey)

        // Verify node connectivity
        do {
            let info = try await rpc.getBlockchainInfo()
            let height = info["height"] as? Int ?? 0
            logger.info("Connected to fbd", metadata: [
                "height": "\(height)",
            ], source: "Pool")
        } catch {
            logger.error("Cannot connect to fbd at \(config.nodeURL): \(error)", source: "Pool")
            throw error
        }

        let shareLog = ShareLog(
            poolFee: config.poolFee,
            windowMultiple: config.pplnsWindowMultiple,
            db: db,
            logger: logger
        )

        let stratum = StratumServer(
            config: config,
            rpc: rpc,
            shareLog: shareLog,
            logger: logger
        )

        // Re-verify pool DB against the chain. Buggy reorg handling could leave
        // pool DB in a stale state in three different ways: (1) blocks marked
        // orphan that the chain still has, (2) mature/credited blocks the
        // chain has since reorged out, (3) payout txs the chain has since
        // reorged out. Each pass corrects one. Idempotent across restarts.
        await Self.reverifyChainState(
            rpc: rpc, db: db, walletName: config.walletName, logger: logger
        )

        // Start maturity checker
        let params = ConsensusParams.params(for: config.network)
        let maturityChecker = MaturityChecker(
            rpc: rpc,
            db: db,
            coinbaseMaturity: params.coinbaseMaturity,
            logger: logger
        )
        maturityChecker.start()

        // Start payout manager (unless disabled)
        var payoutManager: PayoutManager?
        if config.payoutsEnabled {
            let pm = PayoutManager(
                rpc: rpc,
                shareLog: shareLog,
                walletName: config.walletName,
                minPayout: config.minPayout,
                interval: config.payoutInterval,
                logger: logger
            )
            pm.start()
            payoutManager = pm
        } else {
            logger.info("Automatic payouts disabled (--no-payouts)", source: "Pool")
        }

        // Start Stratum
        try stratum.start()

        // Start API
        var api: PoolAPI?
        let apiPort = config.effectiveAPIPort
        if apiPort > 0 {
            let poolAPI = PoolAPI(stratum: stratum, shareLog: shareLog, rpc: rpc, logger: logger)
            do {
                try poolAPI.start(host: config.apiHost, port: Int(apiPort))
                api = poolAPI
            } catch {
                logger.warning("Cannot start API server: \(error)", source: "API")
            }
        }

        // Wait for SIGINT/SIGTERM
        signal(SIGINT) { _ in _poolShouldStop = true }
        signal(SIGTERM) { _ in _poolShouldStop = true }
        while !_poolShouldStop {
            try? await Task.sleep(nanoseconds: 500_000_000)
        }

        logger.info("Shutting down...", source: "Pool")
        maturityChecker.stop()
        payoutManager?.stop()
        api?.shutdown()
        stratum.shutdown()
    }

    /// Re-verify pool DB against the chain in three passes:
    ///
    /// 1. **Orphans → immature**: blocks the pool marked orphan that the chain
    ///    still has. Flip back to immature so MaturityChecker re-credits via
    ///    the normal path.
    /// 2. **Phantom matures → orphan**: blocks the pool marked mature/credited
    ///    that the chain has since reorged away. Mark orphan and reverse the
    ///    miner credits (block_shares is preserved as audit trail).
    /// 3. **Phantom payouts → restored**: payout txs in pool DB whose txid no
    ///    longer exists in the wallet's transaction history (= reorged out).
    ///    Restore the affected miner balances and delete the payout rows.
    ///
    /// Idempotent across restarts. Run before MaturityChecker / PayoutManager
    /// start so they see a consistent state.
    private static func reverifyChainState(
        rpc: NodeRPC, db: PoolDatabase, walletName: String, logger: Logger
    ) async {
        // Pass 1: false orphans → immature
        let orphans = db.getOrphanBlocks()
        var orphanReclaimed = 0
        var realOrphans = 0
        var orphanErrors = 0
        for block in orphans {
            do {
                let (hash, _) = try await rpc.getBlock(height: block.height)
                if hash == block.hash {
                    db.markBlockImmature(height: block.height)
                    orphanReclaimed += 1
                } else {
                    realOrphans += 1
                }
            } catch {
                orphanErrors += 1
            }
        }

        // Pass 2: phantom matures → orphan, reverse credits
        let matures = db.getMatureBlocks()
        var phantomMatures = 0
        var phantomCreditReversed: Int64 = 0
        var matureErrors = 0
        for block in matures {
            do {
                let (hash, _) = try await rpc.getBlock(height: block.height)
                if hash != block.hash {
                    let reversed = db.reverseMatureCredit(height: block.height)
                    phantomMatures += 1
                    phantomCreditReversed += reversed
                }
            } catch {
                matureErrors += 1
            }
        }

        // Pass 3: phantom payouts → restored
        var phantomPayouts = 0
        var phantomPayoutValueRestored: Int64 = 0
        var payoutPassRan = false
        do {
            let walletTxs = try await rpc.listTransactions(walletName: walletName)
            payoutPassRan = true
            // Build set of txids the wallet considers canonical (any type — we
            // include all because a payout could in principle land in any
            // category, and being permissive here only risks NOT reversing
            // a real phantom, never wrongly reversing a real one).
            var walletTxidSet = Set<String>()
            walletTxidSet.reserveCapacity(walletTxs.count)
            for tx in walletTxs { walletTxidSet.insert(tx.txid) }

            for txid in db.getDistinctPayoutTxids() {
                if !walletTxidSet.contains(txid) {
                    let restored = db.reversePayout(txid: txid)
                    phantomPayouts += 1
                    phantomPayoutValueRestored += restored
                }
            }
        } catch {
            logger.warning("Skipping phantom-payout pass: \(error)", source: "Pool")
        }

        logger.info("Chain state reverification complete", metadata: [
            "orphans_reclaimed": "\(orphanReclaimed)",
            "real_orphans": "\(realOrphans)",
            "orphan_errors": "\(orphanErrors)",
            "phantom_matures": "\(phantomMatures)",
            "credit_reversed_fbc": "\(String(format: "%.6f", Double(phantomCreditReversed) / 1_000_000.0))",
            "mature_errors": "\(matureErrors)",
            "phantom_payouts": "\(phantomPayouts)",
            "payout_restored_fbc": "\(String(format: "%.6f", Double(phantomPayoutValueRestored) / 1_000_000.0))",
            "payout_pass": "\(payoutPassRan)",
        ], source: "Pool")
    }
}

#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

nonisolated(unsafe) private var _poolShouldStop = false
