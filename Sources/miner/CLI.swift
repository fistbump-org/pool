import ArgumentParser
import Base
import CBalloon
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

    @Option(name: .shortAndLong, help: "Number of mining threads (default: one per physical core).")
    var threads: Int?

    @Flag(name: .long, help: "Don't pin threads to CPUs — let the kernel schedule. Useful on hybrid CPUs (Intel P+E) where the kernel's thread director migrates work toward P-cores adaptively.")
    var noPin: Bool = false

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

        let physicalCores = max(1, Int(balloon_physical_core_count()))
        logger.info("Fistbump CPU Miner v\(MinerVersion.id)", metadata: [
            "pool": "\(host):\(stratumPort)",
            "user": "\(user)",
            "network": "\(networkType.rawValue)",
            "threads": "\(threads ?? physicalCores)",
            "physical_cores": "\(physicalCores)",
        ], source: "Miner")

        // Self-test: verify C fast path matches C simple path
        selfTestBalloonHash(logger: logger)

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
            pinThreads: !noPin,
            logger: logger
        )

        // When we get a new job, start mining it.
        // clean=true (new block): hard restart threads immediately.
        // clean=false (new transactions): threads pick up new job after current hash finishes.
        client.onNewJob = { [engine, logger] job, clean in
            logger.info("New job: \(job.id) (clean=\(clean))", source: "Miner")
            engine.mine(job: job, clean: clean)
        }

        client.onNewDifficulty = { [engine, logger] diff in
            logger.info("Difficulty set to \(diff)", source: "Miner")
            engine.updateDifficulty(diff)
        }

        // Stats reporting timer + hashrate reporting to pool
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
                // Report actual hashrate to pool for accurate API display
                if s.hashrate > 0 {
                    try? client.reportHashrate(s.hashrate)
                }
            }
        }

        // Ensure cleanup runs even when processMessages() throws on disconnect
        defer {
            statsTask.cancel()
            engine.stop()
            client.disconnect()
        }

        // Read loop — process notifications from pool
        while !Task.isCancelled {
            try client.processMessages()
        }
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

    /// Compare balloon_hash_fast vs balloon_hash_simple at multiple slot counts.
    /// Exits with a fatal error if they diverge.
    private func selfTestBalloonHash(logger: Logger) {
        for testSlots in [64, 1024, 65536] {
            let rounds: Int32 = 1
            let delta: Int32 = 1
            let password: [UInt8] = Array(repeating: 0xAB, count: 32)
            let salt: [UInt8] = Array(repeating: 0xCD, count: 28)

            let bufFast = UnsafeMutablePointer<UInt8>.allocate(capacity: testSlots * 32)
            let bufSimple = UnsafeMutablePointer<UInt8>.allocate(capacity: testSlots * 32)
            let inp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
            let prefetchInp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
            var outFast = [UInt8](repeating: 0, count: 32)
            var outSimple = [UInt8](repeating: 0, count: 32)
            defer { bufFast.deallocate(); bufSimple.deallocate(); inp.deallocate(); prefetchInp.deallocate() }

            password.withUnsafeBufferPointer { pw in
                salt.withUnsafeBufferPointer { sl in
                    outFast.withUnsafeMutableBufferPointer { of in
                        balloon_hash_fast(
                            pw.baseAddress!, Int32(pw.count),
                            sl.baseAddress!, Int32(sl.count),
                            bufFast, inp, prefetchInp,
                            Int32(testSlots), rounds, delta,
                            of.baseAddress!, nil
                        )
                    }
                    outSimple.withUnsafeMutableBufferPointer { os in
                        balloon_hash_simple(
                            pw.baseAddress!, Int32(pw.count),
                            sl.baseAddress!, Int32(sl.count),
                            bufSimple, inp,
                            Int32(testSlots), rounds, delta,
                            os.baseAddress!, nil
                        )
                    }
                }
            }

            if outFast != outSimple {
                logger.error("BalloonHash self-test FAILED at \(testSlots) slots!", source: "Miner")
                logger.error("  fast:   \(HexEncoding.encode(outFast))", source: "Miner")
                logger.error("  simple: \(HexEncoding.encode(outSimple))", source: "Miner")
                fatalError("BalloonHash fast path diverges from simple path — mining results will be invalid")
            }
        }
        logger.info("BalloonHash self-test passed (fast == simple at 64/1K/64K slots)", source: "Miner")
    }
}
