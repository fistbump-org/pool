import Base
import Consensus
import ExtCrypto
import Foundation
import Logging
import Protocol

/// Multi-threaded BalloonHash mining engine for Stratum pool mining.
///
/// Receives jobs from the Stratum client, runs multiple threads iterating
/// nonces, and submits shares (with BalloonProof) when the hash meets the
/// share target.
final class MiningEngine: @unchecked Sendable {
    private let client: StratumClient
    private let params: ConsensusParams
    private let threads: Int
    private let logger: Logger

    private let lock = NSLock()
    private var currentResult: MiningResult?
    private var accepted: Int = 0
    private var rejected: Int = 0
    private var blocks: Int = 0
    private var totalHashes: UInt64 = 0
    private var miningStartTime: Date?

    init(client: StratumClient, network: NetworkType, threads: Int, logger: Logger) {
        self.client = client
        self.params = ConsensusParams.params(for: network)
        self.threads = threads > 0 ? threads : max(1, ProcessInfo.processInfo.activeProcessorCount - 1)
        self.logger = logger
    }

    /// Start mining on a job. Cancels any existing mining work.
    func mine(job: MinerJob) {
        // Stop previous work
        lock.lock()
        currentResult?.stop()
        let result = MiningResult()
        currentResult = result
        if miningStartTime == nil { miningStartTime = Date() }
        lock.unlock()

        let extraNonce1 = client.extraNonce1
        let en2Size = client.extraNonce2Size
        let difficulty = client.difficulty

        // Build the header fields from the job
        let prevBlock = (try? Hash256.fromHex(job.prevHash)) ?? .zero
        let merkleRoot = (try? Hash256.fromHex(job.merkleRoot)) ?? .zero
        let witnessRoot = (try? Hash256.fromHex(job.witnessRoot)) ?? .zero
        let treeRoot = (try? Hash256.fromHex(job.treeRoot)) ?? .zero
        let reservedRoot = (try? Hash256.fromHex(job.reservedRoot)) ?? .zero

        // Compute share target from difficulty
        let shareTarget = targetForDifficulty(difficulty)
        let networkTarget = Target256.fromCompact(job.bits)

        let threadCount = self.threads
        let logger = self.logger
        let params = self.params
        let client = self.client
        let jobId = job.id

        logger.debug("Mining job \(jobId)", metadata: [
            "height_bits": "\(String(format: "0x%08x", job.bits))",
            "difficulty": "\(difficulty)",
            "threads": "\(threadCount)",
        ], source: "Miner")

        for tid in 0..<threadCount {
            Thread.detachNewThread { [weak self] in
                // Each thread gets its own extraNonce2 (thread ID in first bytes)
                var extraNonce2 = [UInt8](repeating: 0, count: en2Size)
                // Encode thread ID into first 2 bytes of extraNonce2
                extraNonce2[0] = UInt8(tid & 0xFF)
                extraNonce2[1] = UInt8((tid >> 8) & 0xFF)

                // Build full extraNonce: pool(8) + en1(4) + en2(12)
                var extraNonce = job.poolExtraNonce
                extraNonce.append(contentsOf: extraNonce1)
                extraNonce.append(contentsOf: extraNonce2)
                if extraNonce.count < 24 {
                    extraNonce.append(contentsOf: [UInt8](repeating: 0, count: 24 - extraNonce.count))
                }

                var nonce = UInt32(tid)
                let stride = UInt32(threadCount)
                var hashes: UInt64 = 0

                while !result.shouldStop {
                    let header = BlockHeader(
                        nonce: nonce,
                        time: job.time,
                        prevBlock: prevBlock,
                        treeRoot: treeRoot,
                        extraNonce: extraNonce,
                        reservedRoot: reservedRoot,
                        witnessRoot: witnessRoot,
                        merkleRoot: merkleRoot,
                        version: job.version,
                        bits: job.bits
                    )

                    let hash: Hash256
                    do {
                        hash = try ProofOfWork.powHash(
                            for: header, params: params,
                            isCancelled: { result.shouldStop }
                        )
                    } catch is BalloonHash.Cancelled {
                        break
                    } catch {
                        logger.error("Thread \(tid) error: \(error)", source: "Miner")
                        return
                    }
                    hashes += 1

                    let hashTarget = Target256(bigEndian: hash.bytes)

                    if hashTarget <= shareTarget {
                        // Found a share! Generate the proof.
                        let isBlock = hashTarget <= networkTarget

                        do {
                            let (_, proof) = try ProofOfWork.powHashWithProof(
                                for: header, params: params
                            )
                            let proofBytes = proof.serialize()

                            let accepted = try client.submit(
                                jobId: jobId,
                                extraNonce2: extraNonce2,
                                nTime: job.time,
                                nonce: nonce,
                                proof: proofBytes
                            )

                            if accepted {
                                self?.recordAccepted()
                                if isBlock {
                                    self?.recordBlock()
                                    logger.info("Block found! nonce=\(nonce)", source: "Miner")
                                } else {
                                    logger.info("Share accepted", metadata: [
                                        "nonce": "\(nonce)",
                                        "thread": "\(tid)",
                                    ], source: "Miner")
                                }
                            } else {
                                self?.recordRejected()
                                logger.warning("Share rejected", source: "Miner")
                            }
                        } catch {
                            logger.error("Submit error: \(error)", source: "Miner")
                        }
                    }

                    let (next, overflow) = nonce.addingReportingOverflow(stride)
                    if overflow { break }
                    nonce = next
                }

                self?.addHashes(hashes)
            }
        }
    }

    /// Stop all mining threads.
    func stop() {
        lock.lock()
        currentResult?.stop()
        lock.unlock()
    }

    /// Get current mining stats.
    var stats: (accepted: Int, rejected: Int, blocks: Int, hashrate: Double) {
        lock.lock()
        defer { lock.unlock() }
        let elapsed = miningStartTime.map { Date().timeIntervalSince($0) } ?? 1
        let hr = elapsed > 0 ? Double(totalHashes) / elapsed : 0
        return (accepted, rejected, blocks, hr)
    }

    // MARK: - Private

    private func recordAccepted() {
        lock.lock()
        accepted += 1
        lock.unlock()
    }

    private func recordRejected() {
        lock.lock()
        rejected += 1
        lock.unlock()
    }

    private func recordBlock() {
        lock.lock()
        blocks += 1
        lock.unlock()
    }

    private func addHashes(_ count: UInt64) {
        lock.lock()
        totalHashes += count
        lock.unlock()
    }

    /// Convert a difficulty value to a 256-bit target.
    private func targetForDifficulty(_ diff: Double) -> Target256 {
        guard diff > 0 else { return params.powLimit }
        if diff <= 1.0 { return params.powLimit }
        let limitBytes = params.powLimit.bigEndianBytes()
        var value = 0.0
        for b in limitBytes {
            value = value * 256.0 + Double(b)
        }
        value /= diff
        var result = [UInt8](repeating: 0, count: 32)
        var remaining = value
        for i in stride(from: 31, through: 0, by: -1) {
            result[i] = UInt8(remaining.truncatingRemainder(dividingBy: 256))
            remaining = (remaining / 256).rounded(.down)
        }
        return Target256(bigEndian: result)
    }
}

// MARK: - Mining Result (thread coordination)

private final class MiningResult: @unchecked Sendable {
    private let lock = NSLock()
    private var _stopped = false

    func stop() {
        lock.lock()
        _stopped = true
        lock.unlock()
    }

    var shouldStop: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _stopped
    }
}
