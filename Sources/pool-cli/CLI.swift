import ArgumentParser
import Base
import Logging

@main
struct PoolCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pool",
        abstract: "Fistbump mining pool — Stratum v1 server with vardiff and PPLNS."
    )

    // MARK: - Node

    @Option(name: .long, help: "fbd RPC URL.")
    var nodeUrl: String?

    @Option(name: .long, help: "fbd RPC API key.")
    var apiKey: String?

    // MARK: - Network

    @Option(name: .shortAndLong, help: "Network: main, testnet, regtest, simnet.")
    var network: String?

    // MARK: - Pool

    @Option(name: .long, help: "Pool coinbase payout address (required).")
    var address: String

    @Option(name: .long, help: "Pool fee percentage (e.g. 1 for 1%).")
    var fee: Double?

    // MARK: - Stratum

    @Option(name: .long, help: "Stratum listen host.")
    var stratumHost: String?

    @Option(name: .long, help: "Stratum listen port (0 = network default).")
    var stratumPort: Int?

    @Option(name: .long, help: "Stratum password for miners.")
    var stratumPassword: String?

    // MARK: - API

    @Option(name: .long, help: "HTTP API listen host.")
    var apiHost: String?

    @Option(name: .long, help: "HTTP API listen port (0 = stratum+1).")
    var apiPort: Int?

    // MARK: - VarDiff

    @Option(name: .long, help: "Target seconds between shares per worker.")
    var vardiffTarget: Double?

    @Option(name: .long, help: "Minimum share difficulty.")
    var minDiff: Double?

    // MARK: - Payouts

    @Option(name: .long, help: "fbd wallet name for payouts (default: primary).")
    var wallet: String?

    @Option(name: .long, help: "Minimum payout in FBC (default: 10).")
    var minPayout: Double?

    @Option(name: .long, help: "Payout check interval in seconds (default: 300).")
    var payoutInterval: Double?

    @Option(name: .long, help: "Data directory for pool state.")
    var datadir: String?

    // MARK: - Logging

    @Option(name: .long, help: "Log level: trace, debug, info, notice, warning, error, critical.")
    var logLevel: String?

    // MARK: - Run

    func run() async throws {
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = parseLogLevel(logLevel ?? "info")
            return handler
        }

        let networkType = NetworkType(rawValue: network ?? "main") ?? .main
        let defaultRPCPort = networkType.rpcPort
        let defaultNodeURL = "http://127.0.0.1:\(defaultRPCPort)"

        let config = PoolConfig(
            network: networkType,
            nodeURL: nodeUrl ?? defaultNodeURL,
            nodeAPIKey: apiKey,
            poolAddress: address,
            stratumHost: stratumHost ?? "0.0.0.0",
            stratumPort: UInt16(clamping: stratumPort ?? 0),
            stratumPassword: stratumPassword,
            apiHost: apiHost ?? "0.0.0.0",
            apiPort: UInt16(clamping: apiPort ?? 0),
            poolFee: (fee ?? 1.0) / 100.0,
            vardiffTargetTime: vardiffTarget ?? 10.0,
            vardiffMinDiff: minDiff ?? 1.0,
            walletName: wallet ?? "primary",
            minPayout: Int64((minPayout ?? 10.0) * 1_000_000),
            payoutInterval: payoutInterval ?? 300,
            dataDir: datadir ?? "~/.fbpool"
        )

        var logger = Logger(label: "org.fistbump.pool")
        logger.logLevel = parseLogLevel(logLevel ?? "info")

        let server = PoolServer(config: config, logger: logger)
        try await server.run()
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
