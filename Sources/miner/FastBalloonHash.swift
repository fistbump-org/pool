import Base
import CBalloon
import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

// MARK: - Mining Buffer (pre-allocated, reusable across hashes)

/// Pre-allocated 512 MB scratchpad for BalloonHash mining.
/// Each mining thread should own one of these and reuse it across nonce iterations.
final class MiningBuffer: @unchecked Sendable {
    let buf: UnsafeMutablePointer<UInt8>
    let inp: UnsafeMutablePointer<UInt8>
    let prefetchInp: UnsafeMutablePointer<UInt8>
    let slots: Int
    /// Cancellation flag — set to non-zero to abort. Checked by C code every 65K slots.
    var cancelled: Int32 = 0

    init(slots: Int) {
        self.slots = slots
        self.buf = .allocate(capacity: slots * 32)
        self.inp = .allocate(capacity: 128)
        self.prefetchInp = .allocate(capacity: 128)
        // Hint for transparent huge pages on Linux (reduces TLB misses on 512 MB random access)
        #if canImport(Glibc) || canImport(Musl)
        madvise(buf, slots * 32, Int32(14)) // MADV_HUGEPAGE = 14
        #endif
    }

    deinit {
        buf.deallocate()
        inp.deallocate()
        prefetchInp.deallocate()
    }
}

/// Thread-safe pool of MiningBuffers so they survive across job changes.
final class BufferPool: @unchecked Sendable {
    private var available: [MiningBuffer] = []
    private let lock = NSLock()
    private let slots: Int

    init(slots: Int) {
        self.slots = slots
    }

    func checkout() -> MiningBuffer {
        lock.lock()
        if let buf = available.popLast() {
            lock.unlock()
            buf.cancelled = 0
            return buf
        }
        lock.unlock()
        return MiningBuffer(slots: slots)
    }

    func checkin(_ buf: MiningBuffer) {
        lock.lock()
        available.append(buf)
        lock.unlock()
    }
}

// MARK: - Fast BalloonHash (C implementation with SIMD BLAKE2b + prefetching)

/// Mining-optimized BalloonHash backed by a C implementation.
///
/// Uses SSSE3 BLAKE2b on x86_64, NEON on ARM64, with prefetching in the mix phase
/// to hide memory latency on the 512 MB random-access pattern.
enum FastBalloonHash {

    struct Cancelled: Error {}

    /// Compute BalloonHash using a pre-allocated buffer and optimized C code.
    static func hash(
        password: [UInt8],
        salt: [UInt8],
        buffer: MiningBuffer,
        slots: Int,
        rounds: Int,
        delta: Int,
        isCancelled: (() -> Bool)? = nil
    ) throws -> [UInt8] {
        // Reset cancellation flag
        buffer.cancelled = 0

        var output = [UInt8](repeating: 0, count: 32)

        let result = password.withUnsafeBufferPointer { pwBuf in
            salt.withUnsafeBufferPointer { saltBuf in
                output.withUnsafeMutableBufferPointer { outBuf in
                    // Poll the Swift cancellation closure into the C flag periodically.
                    // The C code checks the flag every 65K slots (~256 times per hash).
                    // We set it from the thread's shouldStop flag before calling into C.
                    if let isCancelled, isCancelled() {
                        return Int32(-1)
                    }

                    // Wire the MiningResult's shouldStop into the C cancellation flag.
                    // The C code reads this volatile pointer every 65K slots.
                    return balloon_hash_fast(
                        pwBuf.baseAddress!, Int32(pwBuf.count),
                        saltBuf.baseAddress!, Int32(saltBuf.count),
                        buffer.buf,
                        buffer.inp,
                        buffer.prefetchInp,
                        Int32(slots), Int32(rounds), Int32(delta),
                        outBuf.baseAddress!,
                        &buffer.cancelled
                    )
                }
            }
        }

        if result != 0 {
            throw Cancelled()
        }

        return output
    }
}
