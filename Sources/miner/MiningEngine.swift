import Base
import Consensus
import ExtCrypto
import Foundation
import Logging
import Protocol

/// Multi-threaded BalloonHash mining engine for Stratum pool mining.
///
/// Maintains a fixed pool of persistent OS threads that run for the lifetime
/// of a mining session.  Calling `mine(job:)` updates the current job; all
/// threads notice the change via MiningResult cancellation and immediately
/// start mining the new job without being torn down and re-created.  This
/// ensures exactly `threadCount` OS threads are active at all times, regardless
/// of how frequently jobs change.
final class MiningEngine: @unchecked Sendable {
    private let client: StratumClient
    private let params: ConsensusParams
    private let threadCount: Int
    private let logger: Logger

    private let lock = NSLock()
    private var currentJob: MinerJob?
    private var currentResult: MiningResult?
    private var threadsRunning = false
    private var accepted: Int = 0
    private var rejected: Int = 0
    private var blocks: Int = 0
    private var totalHashes: UInt64 = 0
    private var miningStartTime: Date?

    init(client: StratumClient, network: NetworkType, threads: Int, logger: Logger) {
        self.client = client
        self.params = ConsensusParams.params(for: network)
        self.threadCount = threads > 0 ? threads : max(1, ProcessInfo.processInfo.activeProcessorCount - 1)
        self.logger = logger
    }

    /// Update the current job and signal all mining threads to switch to it.
    /// Spawns the thread pool on the very first call.
    func mine(job: MinerJob) {
        lock.lock()
        currentJob = job
        currentResult?.stop()
        let result = MiningResult()
        currentResult = result
        if miningStartTime == nil { miningStartTime = Date() }
        let needsSpawn = !threadsRunning
        if needsSpawn { threadsRunning = true }
        lock.unlock()

        logger.debug("Mining job \(job.id)", metadata: [
            "height_bits": "\(String(format: "0x%08x", job.bits))",
            "difficulty": "\(client.difficulty)",
            "threads": "\(threadCount)",
        ], source: "Miner")

        if needsSpawn {
            let tc = threadCount
            for tid in 0..<tc {
                Thread.detachNewThread { [weak self] in
                    self?.miningLoop(tid: tid, threadStride: UInt32(tc))
                }
            }
        }
    }

    /// Stop all mining threads.
    func stop() {
        lock.lock()
        threadsRunning = false
        currentResult?.stop()
        currentResult = nil
        currentJob = nil
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

    // MARK: - Thread loop

    /// How long a thread sleeps when there is no job yet or the current job
    /// has just been cancelled while a new one is being published.
    private static let jobPollInterval: TimeInterval = 0.005

    /// Persistent per-thread entry point.  Loops forever picking up new jobs
    /// from shared state and exits only when `stop()` has been called.
    private func miningLoop(tid: Int, threadStride: UInt32) {
        while true {
            lock.lock()
            guard threadsRunning else {
                lock.unlock()
                return
            }
            let job = currentJob
            let result = currentResult
            lock.unlock()

            guard let job = job, let result = result, !result.shouldStop else {
                // No work yet or job just changed; spin briefly.
                Thread.sleep(forTimeInterval: Self.jobPollInterval)
                continue
            }

            mineJob(job: job, result: result, tid: tid, threadStride: threadStride)
        }
    }

    /// Mine a single job until the result is cancelled or nonces are exhausted.
    private func mineJob(job: MinerJob, result: MiningResult, tid: Int, threadStride: UInt32) {
        let extraNonce1 = client.extraNonce1
        let en2Size = client.extraNonce2Size
        let difficulty = client.difficulty

        let prevBlock    = (try? Hash256.fromHex(job.prevHash))     ?? .zero
        let merkleRoot   = (try? Hash256.fromHex(job.merkleRoot))   ?? .zero
        let witnessRoot  = (try? Hash256.fromHex(job.witnessRoot))  ?? .zero
        let treeRoot     = (try? Hash256.fromHex(job.treeRoot))     ?? .zero
        let reservedRoot = (try? Hash256.fromHex(job.reservedRoot)) ?? .zero

        let shareTarget  = targetForDifficulty(difficulty)
        let networkTarget = Target256.fromCompact(job.bits)

        // Each thread has its own extraNonce2 (thread ID encoded in first two bytes).
        var extraNonce2 = [UInt8](repeating: 0, count: en2Size)
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

            // Count the attempt before starting the hash so that work done on a
            // cancelled (partial) hash still appears in the hashrate display.
            // BalloonHash is memory-hard and takes several seconds; without this
            // the reported hashrate is always 0 because jobs change faster than
            // individual hashes complete.
            hashes += 1

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
                addHashes(hashes)
                return
            }

            let hashTarget = Target256(bigEndian: hash.bytes)

            if hashTarget <= shareTarget {
                // Found a share — generate the full proof and submit.
                let isBlock = hashTarget <= networkTarget
                do {
                    let (_, proof) = try ProofOfWork.powHashWithProof(
                        for: header, params: params
                    )
                    let proofBytes = proof.serialize()

                    let accepted = try client.submit(
                        jobId: job.id,
                        extraNonce2: extraNonce2,
                        nTime: job.time,
                        nonce: nonce,
                        proof: proofBytes
                    )

                    if accepted {
                        recordAccepted()
                        if isBlock {
                            recordBlock()
                            logger.info("Block found! nonce=\(nonce)", source: "Miner")
                        } else {
                            logger.info("Share accepted", metadata: [
                                "nonce": "\(nonce)",
                                "thread": "\(tid)",
                            ], source: "Miner")
                        }
                    } else {
                        recordRejected()
                        logger.warning("Share rejected", source: "Miner")
                    }
                } catch {
                    logger.error("Submit error: \(error)", source: "Miner")
                }
            }

            let (next, overflow) = nonce.addingReportingOverflow(threadStride)
            if overflow { break }
            nonce = next
        }

        addHashes(hashes)
    }

    // MARK: - Private helpers

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
