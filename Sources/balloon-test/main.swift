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

// MARK: - Run

let b2ok = testBlake2b()
let simpleOk = testBalloonSimple()
let prefetchOk = testBalloonPrefetch()

print("\n=== Summary ===")
print("BLAKE2b:          \(b2ok ? "PASS" : "FAIL")")
print("BalloonHash simple:   \(simpleOk ? "PASS" : "FAIL")")
print("BalloonHash prefetch: \(prefetchOk ? "PASS" : "FAIL")")

if !b2ok || !simpleOk || !prefetchOk {
    print("\nFix the failures above before re-enabling C BalloonHash in the miner.")
    exit(1)
}
print("\nAll tests pass! C implementation matches Swift reference.")
