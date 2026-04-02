import Base
import Foundation
import Logging

/// Main pool orchestrator — wires together Stratum server, share log, and API.
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
        ], source: "Pool")

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
            windowMultiple: config.pplnsWindowMultiple
        )

        let stratum = StratumServer(
            config: config,
            rpc: rpc,
            shareLog: shareLog,
            logger: logger
        )

        stratum.onBlockFound = { [logger] height, hash in
            logger.info("Block \(height) found: \(hash)", source: "Pool")
        }

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

        // Wait for cancellation (SIGINT/SIGTERM)
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            #if canImport(Darwin)
            signal(SIGINT) { _ in
                _poolContinuation?.resume()
                _poolContinuation = nil
            }
            signal(SIGTERM) { _ in
                _poolContinuation?.resume()
                _poolContinuation = nil
            }
            _poolContinuation = continuation
            #else
            let src1 = DispatchSource.makeSignalSource(signal: SIGINT)
            let src2 = DispatchSource.makeSignalSource(signal: SIGTERM)
            src1.setEventHandler { continuation.resume() }
            src2.setEventHandler { continuation.resume() }
            signal(SIGINT, SIG_IGN)
            signal(SIGTERM, SIG_IGN)
            src1.resume()
            src2.resume()
            #endif
        }

        logger.info("Shutting down...", source: "Pool")
        api?.shutdown()
        stratum.shutdown()
    }
}

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

nonisolated(unsafe) private var _poolContinuation: CheckedContinuation<Void, Never>?
