import ArgumentParser
import Base
import Foundation
import Logging

@main
struct MinerCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "miner",
        abstract: "Fistbump CPU miner — connects to a Stratum pool and mines."
    )

    @Option(name: .shortAndLong, help: "Pool host (default: 127.0.0.1).")
    var host: String = "127.0.0.1"

    @Option(name: .shortAndLong, help: "Pool Stratum port.")
    var port: Int?

    @Option(name: .shortAndLong, help: "Username (your payout address, e.g. fb1q...). Append .rigname for multiple rigs.")
    var user: String

    @Option(name: .long, help: "Pool password (if required).")
    var password: String?

    @Option(name: .shortAndLong, help: "Network: main, testnet, regtest, simnet.")
    var network: String?

    @Option(name: .shortAndLong, help: "Number of mining threads (0 = all cores - 1).")
    var threads: Int?

    @Flag(name: .long, help: "Connect to pool using TLS.")
    var tls: Bool = false

    @Option(name: .long, help: "Log level: trace, debug, info, notice, warning, error, critical.")
    var logLevel: String?

    func run() async throws {
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = parseLogLevel(logLevel ?? "info")
            return handler
        }

        var logger = Logger(label: "org.fistbump.miner")
        logger.logLevel = parseLogLevel(logLevel ?? "info")

        let networkType = NetworkType(rawValue: network ?? "main") ?? .main
        let stratumPort = port ?? Int(networkType.stratumPort)

        logger.info("Fistbump CPU Miner", metadata: [
            "pool": "\(host):\(stratumPort)",
            "user": "\(user)",
            "network": "\(networkType.rawValue)",
            "threads": "\(threads ?? (ProcessInfo.processInfo.activeProcessorCount - 1))",
        ], source: "Miner")

        // Connect to pool
        let client = StratumClient(
            host: host,
            port: stratumPort,
            username: user,
            password: password ?? "",
            tls: tls
        )

        var backoff: UInt64 = 2 // seconds
        let maxBackoff: UInt64 = 120

        while !Task.isCancelled {
            do {
                try await miningSession(client: client, networkType: networkType, logger: logger)
                backoff = 2 // reset on clean session
            } catch {
                client.disconnect()
                logger.error("Disconnected: \(error). Reconnecting in \(backoff)s...", source: "Miner")
                try? await Task.sleep(nanoseconds: backoff * 1_000_000_000)
                backoff = min(backoff * 2, maxBackoff)
            }
        }
    }

    private func miningSession(client: StratumClient, networkType: NetworkType, logger: Logger) async throws {
        logger.info("Connecting to \(host):\(port ?? Int(networkType.stratumPort))...", source: "Miner")
        try client.connect()

        logger.info("Subscribing...", source: "Miner")
        try client.subscribe()

        logger.info("Authorizing as \(user)...", source: "Miner")
        try client.authorize()

        logger.info("Connected and authorized. Waiting for work...", source: "Miner")

        let engine = MiningEngine(
            client: client,
            network: networkType,
            threads: threads ?? 0,
            logger: logger
        )

        // When we get a new job, start mining it
        client.onNewJob = { [engine, logger] job, clean in
            logger.info("New job: \(job.id) (clean=\(clean))", source: "Miner")
            engine.mine(job: job)
        }

        client.onNewDifficulty = { [logger] diff in
            logger.info("Difficulty set to \(diff)", source: "Miner")
        }

        // Stats reporting timer
        let statsTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000) // 30s
                let s = engine.stats
                logger.info("Stats", metadata: [
                    "accepted": "\(s.accepted)",
                    "rejected": "\(s.rejected)",
                    "blocks": "\(s.blocks)",
                    "hashrate": "\(String(format: "%.2f", s.hashrate)) H/s",
                ], source: "Miner")
            }
        }

        // Read loop — process notifications from pool
        while !Task.isCancelled {
            try client.processMessages()
        }

        statsTask.cancel()
        engine.stop()
        client.disconnect()
    }

    private func parseLogLevel(_ string: String) -> Logger.Level {
        switch string.lowercased() {
        case "trace":    return .trace
        case "debug":    return .debug
        case "info":     return .info
        case "notice":   return .notice
        case "warning":  return .warning
        case "error":    return .error
        case "critical": return .critical
        default:         return .info
        }
    }
}
