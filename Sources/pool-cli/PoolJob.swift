import Base
import Foundation

/// A mining job distributed to Stratum workers.
///
/// Built from a `BlockTemplateResult` fetched via fbd RPC.
/// Workers vary nonce, extraNonce2, and time to search for valid shares.
public struct PoolJob: Sendable {
    /// Pool extraNonce prefix size (bytes).
    public static let poolExtraNonceSize = 8

    /// Worker extraNonce1 size (bytes).
    public static let extraNonce1Size = 4

    /// Miner-controlled extraNonce2 size (bytes).
    /// Total extraNonce (24) = pool(8) + en1(4) + en2(12).
    public static let extraNonce2Size = 12

    /// Job identifier (hex string).
    public let id: String

    /// Block height.
    public let height: Int

    /// Previous block hash (hex).
    public let prevBlockHash: String

    /// Merkle root (hex, constant for the job).
    public let merkleRoot: String

    /// Witness root (hex).
    public let witnessRoot: String

    /// Tree root (hex).
    public let treeRoot: String

    /// Reserved root (hex, all zeros).
    public let reservedRoot: String

    /// Block version.
    public let version: UInt32

    /// Compact difficulty target (nBits).
    public let bits: UInt32

    /// Block timestamp (LE).
    public let time: UInt64

    /// Pool extraNonce prefix (8 bytes, random per job).
    public let poolExtraNonce: [UInt8]

    /// Network target hex (for block detection).
    public let networkTarget: String

    /// Raw coinbase transaction bytes.
    public let coinbaseData: [UInt8]

    /// Raw transaction data for each non-coinbase tx.
    public let transactionData: [[UInt8]]

    /// Creation timestamp for staleness detection.
    public let createdAt: Date

    /// Create a job from a block template RPC result.
    public static func from(template: BlockTemplateResult, jobId: String) -> PoolJob {
        // Generate random pool extraNonce prefix
        var poolExtraNonce = [UInt8](repeating: 0, count: poolExtraNonceSize)
        for i in 0..<poolExtraNonce.count {
            poolExtraNonce[i] = UInt8.random(in: 0...255)
        }

        let coinbaseData = (try? HexEncoding.decode(template.coinbaseHex)) ?? []
        let txData = template.transactions.compactMap { try? HexEncoding.decode($0.data) }

        return PoolJob(
            id: jobId,
            height: template.height,
            prevBlockHash: template.prevBlockHash,
            merkleRoot: template.merkleRoot,
            witnessRoot: template.witnessRoot,
            treeRoot: template.treeRoot,
            reservedRoot: template.reservedRoot,
            version: template.version,
            bits: template.bits,
            time: template.curTime,
            poolExtraNonce: poolExtraNonce,
            networkTarget: template.target,
            coinbaseData: coinbaseData,
            transactionData: txData,
            createdAt: Date()
        )
    }
}
