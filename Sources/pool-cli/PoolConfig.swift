import Base
import Foundation

/// Configuration for the mining pool.
public struct PoolConfig: Sendable {
    /// Network type (main, testnet, regtest, simnet).
    public let network: NetworkType

    /// fbd RPC URL (e.g. "http://127.0.0.1:32869").
    public let nodeURL: String

    /// fbd RPC API key.
    public let nodeAPIKey: String?

    /// Pool coinbase payout address (Bech32).
    public let poolAddress: String

    /// Stratum listen host.
    public let stratumHost: String

    /// Stratum listen port.
    public let stratumPort: UInt16

    /// Stratum password (nil = no auth).
    public let stratumPassword: String?

    /// HTTP API listen host.
    public let apiHost: String

    /// HTTP API listen port (0 = disabled).
    public let apiPort: UInt16

    /// Pool fee as a fraction (e.g. 0.01 = 1%).
    public let poolFee: Double

    /// PPLNS window size as a multiple of expected shares per block.
    /// E.g. 2.0 means the window holds ~2 blocks worth of shares.
    public let pplnsWindowMultiple: Double

    // MARK: - VarDiff

    /// Target seconds between share submissions per worker.
    public let vardiffTargetTime: Double

    /// Minimum share difficulty.
    public let vardiffMinDiff: Double

    /// Maximum share difficulty.
    public let vardiffMaxDiff: Double

    /// How often to retarget worker difficulty (seconds).
    public let vardiffRetargetTime: Double

    /// Tolerance band — only adjust if share rate deviates by more than this fraction.
    public let vardiffVariance: Double

    // MARK: - Payouts

    /// fbd wallet name to send payouts from.
    public let walletName: String

    /// Minimum balance before a payout is triggered (in bumps).
    public let minPayout: Int64

    /// How often to check for pending payouts (seconds).
    public let payoutInterval: Double

    /// Data directory for persistent state (balances, payout history).
    public let dataDir: String

    public init(
        network: NetworkType = .main,
        nodeURL: String = "http://127.0.0.1:32869",
        nodeAPIKey: String? = nil,
        poolAddress: String,
        stratumHost: String = "0.0.0.0",
        stratumPort: UInt16 = 0,
        stratumPassword: String? = nil,
        apiHost: String = "0.0.0.0",
        apiPort: UInt16 = 0,
        poolFee: Double = 0.01,
        pplnsWindowMultiple: Double = 2.0,
        vardiffTargetTime: Double = 10.0,
        vardiffMinDiff: Double = 1.0,
        vardiffMaxDiff: Double = 1_000_000_000.0,
        vardiffRetargetTime: Double = 60.0,
        vardiffVariance: Double = 0.1,
        walletName: String = "primary",
        minPayout: Int64 = 10_000_000,
        payoutInterval: Double = 300,
        dataDir: String = "~/.fbpool"
    ) {
        self.network = network
        self.nodeURL = nodeURL
        self.nodeAPIKey = nodeAPIKey
        self.poolAddress = poolAddress
        self.stratumHost = stratumHost
        self.stratumPort = stratumPort
        self.stratumPassword = stratumPassword
        self.apiHost = apiHost
        self.apiPort = apiPort
        self.poolFee = poolFee
        self.pplnsWindowMultiple = pplnsWindowMultiple
        self.vardiffTargetTime = vardiffTargetTime
        self.vardiffMinDiff = vardiffMinDiff
        self.vardiffMaxDiff = vardiffMaxDiff
        self.vardiffRetargetTime = vardiffRetargetTime
        self.vardiffVariance = vardiffVariance
        self.walletName = walletName
        self.minPayout = minPayout
        self.payoutInterval = payoutInterval
        self.dataDir = dataDir
    }

    /// The effective Stratum port (config value or network default).
    public var effectiveStratumPort: UInt16 {
        stratumPort != 0 ? stratumPort : network.stratumPort
    }

    /// The effective API port (Stratum port + 1 if not set).
    public var effectiveAPIPort: UInt16 {
        apiPort != 0 ? apiPort : effectiveStratumPort + 1
    }
}
