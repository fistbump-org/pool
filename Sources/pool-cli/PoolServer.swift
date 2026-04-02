import Base
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
        let statePath = dataDir + "/pool-state.json"

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
            dataPath: statePath
        )

        let stratum = StratumServer(
            config: config,
            rpc: rpc,
            shareLog: shareLog,
            logger: logger
        )

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

        // Wait for cancellation (SIGINT/SIGTERM)
        await withCheckedSignal()

        logger.info("Shutting down...", source: "Pool")
        payoutManager.stop()
        api?.shutdown()
        stratum.shutdown()
    }

    private func withCheckedSignal() async {
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
            // Use a single serial queue so that concurrent SIGINT+SIGTERM cannot
            // both pass the optional check and cause a double-resume crash.
            let signalQueue = DispatchQueue(label: "pool.signal")
            let src1 = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
            let src2 = DispatchSource.makeSignalSource(signal: SIGTERM, queue: signalQueue)
            let handler: () -> Void = {
                _poolContinuation?.resume()
                _poolContinuation = nil
                _signalSrc1 = nil
                _signalSrc2 = nil
            }
            src1.setEventHandler(handler: handler)
            src2.setEventHandler(handler: handler)
            signal(SIGINT, SIG_IGN)
            signal(SIGTERM, SIG_IGN)
            src1.resume()
            src2.resume()
            // Retain the sources at module level so they are not deallocated
            // when this closure returns, which would prevent the handlers from firing.
            _signalSrc1 = src1
            _signalSrc2 = src2
            _poolContinuation = continuation
            #endif
        }
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
#if !canImport(Darwin)
nonisolated(unsafe) private var _signalSrc1: DispatchSourceSignal?
nonisolated(unsafe) private var _signalSrc2: DispatchSourceSignal?
#endif
