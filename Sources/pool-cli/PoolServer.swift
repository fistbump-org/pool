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

        // Start maturity checker
        let params = ConsensusParams.params(for: config.network)
        let maturityChecker = MaturityChecker(
            rpc: rpc,
            db: db,
            coinbaseMaturity: params.coinbaseMaturity,
            logger: logger
        )
        maturityChecker.start()

        // Start payout manager
        let payoutManager = PayoutManager(
            rpc: rpc,
            shareLog: shareLog,
            walletName: config.walletName,
            minPayout: config.minPayout,
            interval: config.payoutInterval,
            logger: logger
        )
        payoutManager.start()

        // Start Stratum
        try stratum.start()

        // Start API
        var api: PoolAPI?
        let apiPort = config.effectiveAPIPort
        if apiPort > 0 {
            let poolAPI = PoolAPI(stratum: stratum, shareLog: shareLog, logger: logger)
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
        payoutManager.stop()
        api?.shutdown()
        stratum.shutdown()
    }
}

#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

nonisolated(unsafe) private var _poolShouldStop = false
