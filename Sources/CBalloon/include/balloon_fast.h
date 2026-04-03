#ifndef BALLOON_FAST_H
#define BALLOON_FAST_H

#include <stdint.h>
#include <stddef.h>

/// Compute BalloonHash using a pre-allocated buffer with prefetching.
///
/// - password/password_len: pre-hashed password (typically 32 bytes)
/// - salt/salt_len: nonce + extraNonce (typically 28 bytes)
/// - buf: pre-allocated buffer of slots*32 bytes (NOT zeroed — expand writes every slot)
/// - inp: scratch buffer of at least 128 bytes
/// - prefetch_inp: second scratch buffer of at least 128 bytes (for lookahead)
/// - output: 32-byte result
/// - cancelled: pointer to int flag; checked every 65K slots, returns -1 if set
///
/// Returns 0 on success, -1 if cancelled.
int balloon_hash_fast(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    uint8_t *prefetch_inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
);

#endif
