import Base
import CBalloon
import ExtCrypto
import Foundation

// Test harness: compare C BalloonHash against Swift BalloonHash.
// Uses small slot counts for fast iteration.

func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

// MARK: - Test 1: BLAKE2b-256 comparison

func testBlake2b() -> Bool {
    print("=== Test 1: BLAKE2b-256 ===")
    var pass = true

    let testCases: [(input: [UInt8], label: String)] = [
        ([], "empty"),
        ([0x00], "single zero"),
        (Array(0..<32), "32 bytes"),
        (Array(0..<40), "40 bytes"),
        (Array(0..<68), "68 bytes"),
        (Array(0..<72), "72 bytes"),
        (Array(0..<128), "128 bytes"),
    ]

    for tc in testCases {
        // Swift BLAKE2b (from fbd ExtCrypto — the reference)
        let swiftHash = try! Blake2bHash.hash(tc.input, size: 32)

        // C BLAKE2b (from CBalloon)
        var cHash = [UInt8](repeating: 0, count: 32)
        tc.input.withUnsafeBufferPointer { inBuf in
            cHash.withUnsafeMutableBufferPointer { outBuf in
                balloon_blake2b256_test(
                    inBuf.baseAddress ?? UnsafePointer(bitPattern: 1)!,
                    Int32(tc.input.count),
                    outBuf.baseAddress!
                )
            }
        }

        let match = swiftHash == cHash
        if !match {
            print("  FAIL \(tc.label): swift=\(hexString(swiftHash)) c=\(hexString(cHash))")
            pass = false
        } else {
            print("  ok   \(tc.label): \(hexString(swiftHash))")
        }
    }
    return pass
}

// MARK: - Test 2: Simple C BalloonHash (no prefetch) vs Swift

func testBalloonSimple() -> Bool {
    print("\n=== Test 2: BalloonHash simple (no prefetch) ===")
    var pass = true

    let password: [UInt8] = Array(0..<32)
    let salt: [UInt8] = Array(100..<128)

    for slots in [16, 64, 256] {
        let swiftResult = try! BalloonHash.hash(
            password: password, salt: salt,
            slots: slots, rounds: 1, delta: 1
        )

        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: slots * 32)
        let inp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
        defer { buf.deallocate(); inp.deallocate() }

        var cResult = [UInt8](repeating: 0, count: 32)
        let rc = password.withUnsafeBufferPointer { pw in
            salt.withUnsafeBufferPointer { sl in
                cResult.withUnsafeMutableBufferPointer { out in
                    balloon_hash_simple(
                        pw.baseAddress!, Int32(pw.count),
                        sl.baseAddress!, Int32(sl.count),
                        buf, inp,
                        Int32(slots), Int32(1), Int32(1),
                        out.baseAddress!, nil
                    )
                }
            }
        }

        let match = rc == 0 && swiftResult == cResult
        if !match {
            print("  FAIL slots=\(slots): swift=\(hexString(swiftResult)) c=\(hexString(cResult))")
            pass = false
        } else {
            print("  ok   slots=\(slots): \(hexString(swiftResult))")
        }
    }
    return pass
}

// MARK: - Test 3: Prefetch C BalloonHash vs Swift

func testBalloonPrefetch() -> Bool {
    print("\n=== Test 3: BalloonHash with prefetch ===")
    var pass = true

    let password: [UInt8] = Array(0..<32)
    let salt: [UInt8] = Array(100..<128)

    for slots in [16, 64, 256, 4096, 65536] {
        let swiftResult = try! BalloonHash.hash(
            password: password, salt: salt,
            slots: slots, rounds: 1, delta: 1
        )

        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: slots * 32)
        let inp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
        let pfInp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
        defer { buf.deallocate(); inp.deallocate(); pfInp.deallocate() }

        var cResult = [UInt8](repeating: 0, count: 32)
        let rc = password.withUnsafeBufferPointer { pw in
            salt.withUnsafeBufferPointer { sl in
                cResult.withUnsafeMutableBufferPointer { out in
                    balloon_hash_fast(
                        pw.baseAddress!, Int32(pw.count),
                        sl.baseAddress!, Int32(sl.count),
                        buf, inp, pfInp,
                        Int32(slots), Int32(1), Int32(1),
                        out.baseAddress!, nil
                    )
                }
            }
        }

        let match = rc == 0 && swiftResult == cResult
        if !match {
            print("  FAIL slots=\(slots): swift=\(hexString(swiftResult)) c=\(hexString(cResult))")
            pass = false
        } else {
            print("  ok   slots=\(slots): \(hexString(swiftResult))")
        }
    }
    return pass
}

// MARK: - Test 4: AVX2 4-way batch BLAKE2b vs 4× single-block

func testBlake2bX4() -> Bool {
    print("\n=== Test 4: BLAKE2b-256 4-way (AVX2 batch) ===")
    guard balloon_has_avx2_x4() != 0 else {
        print("  skip (not an AVX2 build)")
        return true
    }
    var pass = true
    // Mix of hand-picked and pseudo-random 32-byte inputs.
    let inputs: [[UInt8]] = [
        Array(0..<32),
        Array(repeating: 0xAA, count: 32),
        (0..<32).map { UInt8(($0 * 17 + 5) & 0xFF) },
        (0..<32).map { UInt8(($0 * 131 ^ 0x5A) & 0xFF) },
        Array(100..<132),
        (0..<32).map { _ in UInt8.random(in: 0...255) },
        (0..<32).map { _ in UInt8.random(in: 0...255) },
        (0..<32).map { _ in UInt8.random(in: 0...255) },
    ]
    // Batch them in groups of 4.
    for batchIdx in 0..<(inputs.count / 4) {
        let b = Array(inputs[(batchIdx * 4)..<(batchIdx * 4 + 4)])

        // Scalar reference
        var ref = [[UInt8]](repeating: [UInt8](repeating: 0, count: 32), count: 4)
        for k in 0..<4 {
            var out = [UInt8](repeating: 0, count: 32)
            b[k].withUnsafeBufferPointer { ib in
                out.withUnsafeMutableBufferPointer { ob in
                    balloon_blake2b256_test(ib.baseAddress!, 32, ob.baseAddress!)
                }
            }
            ref[k] = out
        }

        // Batch (separate locals avoid Swift's exclusivity rules).
        var g0 = [UInt8](repeating: 0, count: 32)
        var g1 = [UInt8](repeating: 0, count: 32)
        var g2 = [UInt8](repeating: 0, count: 32)
        var g3 = [UInt8](repeating: 0, count: 32)
        b[0].withUnsafeBufferPointer { i0 in
            b[1].withUnsafeBufferPointer { i1 in
                b[2].withUnsafeBufferPointer { i2 in
                    b[3].withUnsafeBufferPointer { i3 in
                        g0.withUnsafeMutableBufferPointer { o0 in
                            g1.withUnsafeMutableBufferPointer { o1 in
                                g2.withUnsafeMutableBufferPointer { o2 in
                                    g3.withUnsafeMutableBufferPointer { o3 in
                                        balloon_blake2b256_x4_test(
                                            i0.baseAddress!, i1.baseAddress!,
                                            i2.baseAddress!, i3.baseAddress!,
                                            o0.baseAddress!, o1.baseAddress!,
                                            o2.baseAddress!, o3.baseAddress!
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let got = [g0, g1, g2, g3]
        for k in 0..<4 {
            if ref[k] != got[k] {
                print("  FAIL batch \(batchIdx) lane \(k): ref=\(hexString(ref[k])) x4=\(hexString(got[k]))")
                pass = false
            } else {
                print("  ok   batch \(batchIdx) lane \(k): \(hexString(ref[k]))")
            }
        }
    }
    return pass
}

// MARK: - Test 5: BalloonHash prefetch with rounds/delta > 1

func testBalloonPrefetchLarger() -> Bool {
    print("\n=== Test 5: BalloonHash prefetch (rounds > 1, delta > 1) ===")
    var pass = true
    let password: [UInt8] = Array(0..<32)
    let salt: [UInt8] = Array(100..<128)
    // (slots, rounds, delta) — exercises the refill path across multiple
    // slot/round/delta boundaries on the AVX2 batched loop.
    let cases: [(Int, Int, Int)] = [
        (64, 2, 1), (64, 1, 3), (64, 2, 2),
        (256, 2, 2), (4096, 1, 2),
    ]
    for (slots, rounds, delta) in cases {
        let swiftResult = try! BalloonHash.hash(
            password: password, salt: salt,
            slots: slots, rounds: rounds, delta: delta
        )
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: slots * 32)
        let inp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
        let pfInp = UnsafeMutablePointer<UInt8>.allocate(capacity: 128)
        defer { buf.deallocate(); inp.deallocate(); pfInp.deallocate() }

        var cResult = [UInt8](repeating: 0, count: 32)
        let rc = password.withUnsafeBufferPointer { pw in
            salt.withUnsafeBufferPointer { sl in
                cResult.withUnsafeMutableBufferPointer { out in
                    balloon_hash_fast(
                        pw.baseAddress!, Int32(pw.count),
                        sl.baseAddress!, Int32(sl.count),
                        buf, inp, pfInp,
                        Int32(slots), Int32(rounds), Int32(delta),
                        out.baseAddress!, nil
                    )
                }
            }
        }
        let label = "slots=\(slots) rounds=\(rounds) delta=\(delta)"
        if rc == 0 && swiftResult == cResult {
            print("  ok   \(label): \(hexString(swiftResult))")
        } else {
            print("  FAIL \(label): swift=\(hexString(swiftResult)) c=\(hexString(cResult))")
            pass = false
        }
    }
    return pass
}

// MARK: - Run

let b2ok = testBlake2b()
let simpleOk = testBalloonSimple()
let prefetchOk = testBalloonPrefetch()
let x4ok = testBlake2bX4()
let largerOk = testBalloonPrefetchLarger()

print("\n=== Summary ===")
print("BLAKE2b:                 \(b2ok ? "PASS" : "FAIL")")
print("BalloonHash simple:      \(simpleOk ? "PASS" : "FAIL")")
print("BalloonHash prefetch:    \(prefetchOk ? "PASS" : "FAIL")")
print("BLAKE2b x4 (AVX2 batch): \(x4ok ? "PASS" : "FAIL")")
print("BalloonHash larger r/d:  \(largerOk ? "PASS" : "FAIL")")

if !b2ok || !simpleOk || !prefetchOk || !x4ok || !largerOk {
    print("\nFix the failures above before re-enabling C BalloonHash in the miner.")
    exit(1)
}
print("\nAll tests pass! C implementation matches Swift reference.")
