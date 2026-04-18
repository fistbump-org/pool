#include "balloon_fast.h"
#include <string.h>
#include <stdlib.h>
#if defined(__linux__)
#include <sys/mman.h>
#endif

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

// SSSE3 BLAKE2b for x86-64 (validated against balloon-test vectors).
#if defined(__x86_64__) && defined(__SSSE3__)
    #include <tmmintrin.h>
    #define BLAKE2B_SSSE3 1
#elif defined(__aarch64__) || defined(_M_ARM64)
  #include <arm_neon.h>
  #define BLAKE2B_NEON 1
#endif

// 4-way interleaved BLAKE2b-256 for batching independent index-computations
// in Phase 2. Each YMM lane holds one instance's state word; the four lanes
// run fully independently, so no cross-lane shuffles are needed (the part
// that makes AVX2 a poor fit for SINGLE-block BLAKE2b).
#if defined(__x86_64__) && defined(__AVX2__)
    #include <immintrin.h>
    #define BLAKE2B_X4_AVX2 1
#endif

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static inline void store_u64le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

static inline uint64_t load_u64le(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void copy32(const uint8_t *src, uint8_t *dst) {
    memcpy(dst, src, 32);
}

// BLAKE2b IV
static const uint64_t iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// Sigma schedule (12 rounds × 16 entries, flat)
static const uint8_t sigma[192] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
    11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4,
     7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8,
     9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13,
     2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9,
    12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11,
    13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10,
     6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5,
    10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
};

// ---------------------------------------------------------------------------
// BLAKE2b-256 single-block: SSSE3 implementation
// ---------------------------------------------------------------------------

#if BLAKE2B_SSSE3

// Shuffle masks for 64-bit lane rotations via SSSE3 _mm_shuffle_epi8.
// Each mask maps output[i] = input[(i+N)%8] within each 64-bit lane.
// ROTR16: shift each 64-bit lane right by 16 bits (2 bytes)
static const uint8_t ROT16[16] __attribute__((aligned(16))) = {
    2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9
};
// ROTR24: shift each 64-bit lane right by 24 bits (3 bytes)
static const uint8_t ROT24[16] __attribute__((aligned(16))) = {
    3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10
};

#define ROTR32(x)  _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))
#define ROTR24(x)  _mm_shuffle_epi8((x), *(const __m128i*)ROT24)
#define ROTR16(x)  _mm_shuffle_epi8((x), *(const __m128i*)ROT16)
#define ROTR63(x)  _mm_xor_si128(_mm_srli_epi64((x), 63), _mm_add_epi64((x), (x)))

#define G1(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1)  \
    r1l = _mm_add_epi64(_mm_add_epi64(r1l, b0), r2l); \
    r1h = _mm_add_epi64(_mm_add_epi64(r1h, b1), r2h); \
    r4l = _mm_xor_si128(r4l, r1l); r4h = _mm_xor_si128(r4h, r1h); \
    r4l = ROTR32(r4l); r4h = ROTR32(r4h); \
    r3l = _mm_add_epi64(r3l, r4l); r3h = _mm_add_epi64(r3h, r4h); \
    r2l = _mm_xor_si128(r2l, r3l); r2h = _mm_xor_si128(r2h, r3h); \
    r2l = ROTR24(r2l); r2h = ROTR24(r2h);

#define G2(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1)  \
    r1l = _mm_add_epi64(_mm_add_epi64(r1l, b0), r2l); \
    r1h = _mm_add_epi64(_mm_add_epi64(r1h, b1), r2h); \
    r4l = _mm_xor_si128(r4l, r1l); r4h = _mm_xor_si128(r4h, r1h); \
    r4l = ROTR16(r4l); r4h = ROTR16(r4h); \
    r3l = _mm_add_epi64(r3l, r4l); r3h = _mm_add_epi64(r3h, r4h); \
    r2l = _mm_xor_si128(r2l, r3l); r2h = _mm_xor_si128(r2h, r3h); \
    r2l = ROTR63(r2l); r2h = ROTR63(r2h);

#define DIAG(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    __m128i t0, t1; \
    t0 = _mm_alignr_epi8(r2h, r2l, 8); t1 = _mm_alignr_epi8(r2l, r2h, 8); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = _mm_alignr_epi8(r4h, r4l, 8); t1 = _mm_alignr_epi8(r4l, r4h, 8); \
    r4l = t1; r4h = t0; \
}

#define UNDIAG(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    __m128i t0, t1; \
    t0 = _mm_alignr_epi8(r2l, r2h, 8); t1 = _mm_alignr_epi8(r2h, r2l, 8); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = _mm_alignr_epi8(r4l, r4h, 8); t1 = _mm_alignr_epi8(r4h, r4l, 8); \
    r4l = t1; r4h = t0; \
}

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    // Load message words (zero-padded)
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    // State init: h = IV ^ param_block (digest=32, key=0, fanout=1, depth=1)
    __m128i row1l = _mm_set_epi64x((long long)iv[1], (long long)(iv[0] ^ 0x01010020ULL));
    __m128i row1h = _mm_set_epi64x((long long)iv[3], (long long)iv[2]);
    __m128i row2l = _mm_set_epi64x((long long)iv[5], (long long)iv[4]);
    __m128i row2h = _mm_set_epi64x((long long)iv[7], (long long)iv[6]);
    __m128i row3l = _mm_set_epi64x((long long)iv[1], (long long)iv[0]);
    __m128i row3h = _mm_set_epi64x((long long)iv[3], (long long)iv[2]);
    __m128i row4l = _mm_set_epi64x((long long)iv[5], (long long)(iv[4] ^ (uint64_t)len));
    __m128i row4h = _mm_set_epi64x((long long)iv[7], (long long)(~iv[6]));

    // Save initial state for finalization (only first 4 words needed for 256-bit)
    __m128i orig1l = row1l, orig1h = row1h;

    // 12 rounds
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        __m128i b0, b1;

        // Column step: G1 adds x words, G2 adds y words
        // G(v0,..,m[s[0]],m[s[1]]), G(v1,..,m[s[2]],m[s[3]]),
        // G(v2,..,m[s[4]],m[s[5]]), G(v3,..,m[s[6]],m[s[7]])
        // row1l=(v0,v1), row1h=(v2,v3) → b0 low=v0's word, b0 high=v1's word
        b0 = _mm_set_epi64x((long long)m[s[2]], (long long)m[s[0]]);   // x: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[6]], (long long)m[s[4]]);   // x: v2, v3
        G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = _mm_set_epi64x((long long)m[s[3]], (long long)m[s[1]]);   // y: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[7]], (long long)m[s[5]]);   // y: v2, v3
        G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        // Diagonalize
        DIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

        // Diagonal step
        b0 = _mm_set_epi64x((long long)m[s[10]], (long long)m[s[8]]);  // x: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[14]], (long long)m[s[12]]); // x: v2, v3
        G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = _mm_set_epi64x((long long)m[s[11]], (long long)m[s[9]]);  // y: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[15]], (long long)m[s[13]]); // y: v2, v3
        G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        // Undiagonalize
        UNDIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);
    }

    // Finalize: h ^= v[0..3] ^ v[8..11] (only 256 bits needed)
    row1l = _mm_xor_si128(_mm_xor_si128(orig1l, row1l), row3l);
    row1h = _mm_xor_si128(_mm_xor_si128(orig1h, row1h), row3h);

    _mm_storeu_si128((__m128i *)(output),      row1l);
    _mm_storeu_si128((__m128i *)(output + 16), row1h);
}

// ---------------------------------------------------------------------------
// BLAKE2b-256 single-block: NEON implementation
// ---------------------------------------------------------------------------

#elif BLAKE2B_NEON

#define ROTR32(x) vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(x)))
#define ROTR24(x) vorrq_u64(vshrq_n_u64(x, 24), vshlq_n_u64(x, 40))
#define ROTR16(x) vorrq_u64(vshrq_n_u64(x, 16), vshlq_n_u64(x, 48))
#define ROTR63(x) veorq_u64(vshrq_n_u64(x, 63), vaddq_u64(x, x))

// Full 4-wide G macros: 8-register layout (matches SSSE3 structure).
// Each row is split into low (lanes 0-1) and high (lanes 2-3) uint64x2_t pairs.
#define G1N(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1) \
    r1l = vaddq_u64(vaddq_u64(r1l, b0), r2l); \
    r1h = vaddq_u64(vaddq_u64(r1h, b1), r2h); \
    r4l = veorq_u64(r4l, r1l); r4h = veorq_u64(r4h, r1h); \
    r4l = ROTR32(r4l); r4h = ROTR32(r4h); \
    r3l = vaddq_u64(r3l, r4l); r3h = vaddq_u64(r3h, r4h); \
    r2l = veorq_u64(r2l, r3l); r2h = veorq_u64(r2h, r3h); \
    r2l = ROTR24(r2l); r2h = ROTR24(r2h);

#define G2N(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1) \
    r1l = vaddq_u64(vaddq_u64(r1l, b0), r2l); \
    r1h = vaddq_u64(vaddq_u64(r1h, b1), r2h); \
    r4l = veorq_u64(r4l, r1l); r4h = veorq_u64(r4h, r1h); \
    r4l = ROTR16(r4l); r4h = ROTR16(r4h); \
    r3l = vaddq_u64(r3l, r4l); r3h = vaddq_u64(r3h, r4h); \
    r2l = veorq_u64(r2l, r3l); r2h = veorq_u64(r2h, r3h); \
    r2l = ROTR63(r2l); r2h = ROTR63(r2h);

#define DIAG_NEON(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    uint64x2_t t0, t1; \
    t0 = vextq_u64(r2l, r2h, 1); t1 = vextq_u64(r2h, r2l, 1); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = vextq_u64(r4l, r4h, 1); t1 = vextq_u64(r4h, r4l, 1); \
    r4l = t1; r4h = t0; \
}

#define UNDIAG_NEON(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    uint64x2_t t0, t1; \
    t0 = vextq_u64(r2h, r2l, 1); t1 = vextq_u64(r2l, r2h, 1); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = vextq_u64(r4h, r4l, 1); t1 = vextq_u64(r4l, r4h, 1); \
    r4l = t1; r4h = t0; \
}

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    // State init: h = IV ^ param_block (digest=32, key=0, fanout=1, depth=1)
    uint64x2_t row1l = vcombine_u64(vcreate_u64(iv[0] ^ 0x01010020ULL), vcreate_u64(iv[1]));
    uint64x2_t row1h = vcombine_u64(vcreate_u64(iv[2]), vcreate_u64(iv[3]));
    uint64x2_t row2l = vcombine_u64(vcreate_u64(iv[4]), vcreate_u64(iv[5]));
    uint64x2_t row2h = vcombine_u64(vcreate_u64(iv[6]), vcreate_u64(iv[7]));
    uint64x2_t row3l = vcombine_u64(vcreate_u64(iv[0]), vcreate_u64(iv[1]));
    uint64x2_t row3h = vcombine_u64(vcreate_u64(iv[2]), vcreate_u64(iv[3]));
    uint64x2_t row4l = vcombine_u64(vcreate_u64(iv[4] ^ (uint64_t)len), vcreate_u64(iv[5]));
    uint64x2_t row4h = vcombine_u64(vcreate_u64(~iv[6]), vcreate_u64(iv[7]));

    // Save initial state for finalization (only first 4 words needed for 256-bit)
    uint64x2_t orig1l = row1l, orig1h = row1h;

    // 12 rounds
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        uint64x2_t b0, b1;

        // Column step
        b0 = vcombine_u64(vcreate_u64(m[s[0]]), vcreate_u64(m[s[2]]));
        b1 = vcombine_u64(vcreate_u64(m[s[4]]), vcreate_u64(m[s[6]]));
        G1N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = vcombine_u64(vcreate_u64(m[s[1]]), vcreate_u64(m[s[3]]));
        b1 = vcombine_u64(vcreate_u64(m[s[5]]), vcreate_u64(m[s[7]]));
        G2N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        DIAG_NEON(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

        // Diagonal step
        b0 = vcombine_u64(vcreate_u64(m[s[8]]), vcreate_u64(m[s[10]]));
        b1 = vcombine_u64(vcreate_u64(m[s[12]]), vcreate_u64(m[s[14]]));
        G1N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = vcombine_u64(vcreate_u64(m[s[9]]), vcreate_u64(m[s[11]]));
        b1 = vcombine_u64(vcreate_u64(m[s[13]]), vcreate_u64(m[s[15]]));
        G2N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        UNDIAG_NEON(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);
    }

    // Finalize: h ^= v[0..3] ^ v[8..11] (only 256 bits needed)
    row1l = veorq_u64(veorq_u64(orig1l, row1l), row3l);
    row1h = veorq_u64(veorq_u64(orig1h, row1h), row3h);

    vst1q_u8(output,      vreinterpretq_u8_u64(row1l));
    vst1q_u8(output + 16, vreinterpretq_u8_u64(row1h));
}

// ---------------------------------------------------------------------------
// BLAKE2b-256 single-block: scalar fallback
// ---------------------------------------------------------------------------

#else

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    uint64_t h0 = iv[0] ^ 0x01010020ULL, h1 = iv[1], h2 = iv[2], h3 = iv[3];

    uint64_t v[16];
    v[0]=h0; v[1]=h1; v[2]=h2; v[3]=h3;
    v[4]=iv[4]; v[5]=iv[5]; v[6]=iv[6]; v[7]=iv[7];
    v[8]=iv[0]; v[9]=iv[1]; v[10]=iv[2]; v[11]=iv[3];
    v[12]=iv[4]^(uint64_t)len; v[13]=iv[5]; v[14]=~iv[6]; v[15]=iv[7];

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        #define MIX(a,b,c,d,x,y) \
            v[a]=v[a]+v[b]+x; v[d]^=v[a]; v[d]=(v[d]>>32)|(v[d]<<32); \
            v[c]=v[c]+v[d]; v[b]^=v[c]; v[b]=(v[b]>>24)|(v[b]<<40); \
            v[a]=v[a]+v[b]+y; v[d]^=v[a]; v[d]=(v[d]>>16)|(v[d]<<48); \
            v[c]=v[c]+v[d]; v[b]^=v[c]; v[b]=(v[b]>>63)|(v[b]<<1);
        MIX(0,4, 8,12,m[s[0]],m[s[1]]); MIX(1,5, 9,13,m[s[2]],m[s[3]]);
        MIX(2,6,10,14,m[s[4]],m[s[5]]); MIX(3,7,11,15,m[s[6]],m[s[7]]);
        MIX(0,5,10,15,m[s[8]],m[s[9]]); MIX(1,6,11,12,m[s[10]],m[s[11]]);
        MIX(2,7, 8,13,m[s[12]],m[s[13]]); MIX(3,4, 9,14,m[s[14]],m[s[15]]);
        #undef MIX
    }

    store_u64le(output,      h0 ^ v[0] ^ v[8]);
    store_u64le(output + 8,  h1 ^ v[1] ^ v[9]);
    store_u64le(output + 16, h2 ^ v[2] ^ v[10]);
    store_u64le(output + 24, h3 ^ v[3] ^ v[11]);
}

#endif

// ---------------------------------------------------------------------------
// 4-way interleaved BLAKE2b-256 (AVX2) — single-block, 32-byte inputs.
//
// Used only by the Phase-2 mix loop on x86_64+AVX2 to hash 4 independent
// (counter, round, i, j) tuples in parallel. State is interleaved so lane k
// of each ymm register holds instance k's word — lanes are fully independent,
// so no cross-lane permutes are needed.
// ---------------------------------------------------------------------------

#if BLAKE2B_X4_AVX2

// Byte-shuffle masks for 64-bit lane rotations. _mm256_shuffle_epi8 operates
// per-128-bit-half, so each 16-byte mask is duplicated.
static const uint8_t ROT16_X4[32] __attribute__((aligned(32))) = {
    2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9,
    2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9,
};
static const uint8_t ROT24_X4[32] __attribute__((aligned(32))) = {
    3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10,
    3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10,
};

#define ROTR32_X4(x)  _mm256_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))
#define ROTR24_X4(x)  _mm256_shuffle_epi8((x), *(const __m256i *)ROT24_X4)
#define ROTR16_X4(x)  _mm256_shuffle_epi8((x), *(const __m256i *)ROT16_X4)
#define ROTR63_X4(x)  _mm256_or_si256(_mm256_add_epi64((x), (x)), \
                                      _mm256_srli_epi64((x), 63))

#define GX4(a,b,c,d,x,y) \
    a = _mm256_add_epi64(_mm256_add_epi64(a, b), x); \
    d = ROTR32_X4(_mm256_xor_si256(d, a)); \
    c = _mm256_add_epi64(c, d); \
    b = ROTR24_X4(_mm256_xor_si256(b, c)); \
    a = _mm256_add_epi64(_mm256_add_epi64(a, b), y); \
    d = ROTR16_X4(_mm256_xor_si256(d, a)); \
    c = _mm256_add_epi64(c, d); \
    b = ROTR63_X4(_mm256_xor_si256(b, c));

/// Hash 4 independent 32-byte inputs, producing 4 × 32-byte outputs.
/// Every lane has input length 32 and is the final block.
static void blake2b256_x4_32byte(
    const uint8_t *in0, const uint8_t *in1,
    const uint8_t *in2, const uint8_t *in3,
    uint8_t *out0, uint8_t *out1,
    uint8_t *out2, uint8_t *out3
) {
    // Load message words: m[k] holds word k from each of the 4 instances.
    // For a 32-byte input, only m[0..3] are populated; m[4..15] are zero.
    __m256i m[16];
    const uint8_t *ins[4] = { in0, in1, in2, in3 };
    for (int k = 0; k < 4; k++) {
        uint64_t w[4];
        for (int l = 0; l < 4; l++) w[l] = load_u64le(ins[l] + 8 * k);
        m[k] = _mm256_set_epi64x((long long)w[3], (long long)w[2],
                                 (long long)w[1], (long long)w[0]);
    }
    __m256i zero = _mm256_setzero_si256();
    for (int k = 4; k < 16; k++) m[k] = zero;

    // State init: broadcast across lanes since all 4 instances share
    // length (32) and parameter-block / final-block flags.
    __m256i v[16];
    v[0]  = _mm256_set1_epi64x((long long)(iv[0] ^ 0x01010020ULL));
    v[1]  = _mm256_set1_epi64x((long long)iv[1]);
    v[2]  = _mm256_set1_epi64x((long long)iv[2]);
    v[3]  = _mm256_set1_epi64x((long long)iv[3]);
    v[4]  = _mm256_set1_epi64x((long long)iv[4]);
    v[5]  = _mm256_set1_epi64x((long long)iv[5]);
    v[6]  = _mm256_set1_epi64x((long long)iv[6]);
    v[7]  = _mm256_set1_epi64x((long long)iv[7]);
    v[8]  = _mm256_set1_epi64x((long long)iv[0]);
    v[9]  = _mm256_set1_epi64x((long long)iv[1]);
    v[10] = _mm256_set1_epi64x((long long)iv[2]);
    v[11] = _mm256_set1_epi64x((long long)iv[3]);
    v[12] = _mm256_set1_epi64x((long long)(iv[4] ^ (uint64_t)32));
    v[13] = _mm256_set1_epi64x((long long)iv[5]);
    v[14] = _mm256_set1_epi64x((long long)(~iv[6]));
    v[15] = _mm256_set1_epi64x((long long)iv[7]);

    __m256i orig0 = v[0], orig1 = v[1], orig2 = v[2], orig3 = v[3];

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        // Column step
        GX4(v[0], v[4], v[ 8], v[12], m[s[ 0]], m[s[ 1]]);
        GX4(v[1], v[5], v[ 9], v[13], m[s[ 2]], m[s[ 3]]);
        GX4(v[2], v[6], v[10], v[14], m[s[ 4]], m[s[ 5]]);
        GX4(v[3], v[7], v[11], v[15], m[s[ 6]], m[s[ 7]]);
        // Diagonal step
        GX4(v[0], v[5], v[10], v[15], m[s[ 8]], m[s[ 9]]);
        GX4(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        GX4(v[2], v[7], v[ 8], v[13], m[s[12]], m[s[13]]);
        GX4(v[3], v[4], v[ 9], v[14], m[s[14]], m[s[15]]);
    }

    // Finalize: h[i] ^= v[i] ^ v[i+8]. Only first 4 state words for 256-bit.
    __m256i h0 = _mm256_xor_si256(_mm256_xor_si256(orig0, v[0]), v[ 8]);
    __m256i h1 = _mm256_xor_si256(_mm256_xor_si256(orig1, v[1]), v[ 9]);
    __m256i h2 = _mm256_xor_si256(_mm256_xor_si256(orig2, v[2]), v[10]);
    __m256i h3 = _mm256_xor_si256(_mm256_xor_si256(orig3, v[3]), v[11]);

    // De-interleave: lane i of hk is instance i's word k.
    uint8_t *outs[4] = { out0, out1, out2, out3 };
    uint64_t h[4][4];
    // Scalar extract — 16 extracts is negligible vs 12 rounds.
    h[0][0] = (uint64_t)_mm256_extract_epi64(h0, 0);
    h[1][0] = (uint64_t)_mm256_extract_epi64(h0, 1);
    h[2][0] = (uint64_t)_mm256_extract_epi64(h0, 2);
    h[3][0] = (uint64_t)_mm256_extract_epi64(h0, 3);
    h[0][1] = (uint64_t)_mm256_extract_epi64(h1, 0);
    h[1][1] = (uint64_t)_mm256_extract_epi64(h1, 1);
    h[2][1] = (uint64_t)_mm256_extract_epi64(h1, 2);
    h[3][1] = (uint64_t)_mm256_extract_epi64(h1, 3);
    h[0][2] = (uint64_t)_mm256_extract_epi64(h2, 0);
    h[1][2] = (uint64_t)_mm256_extract_epi64(h2, 1);
    h[2][2] = (uint64_t)_mm256_extract_epi64(h2, 2);
    h[3][2] = (uint64_t)_mm256_extract_epi64(h2, 3);
    h[0][3] = (uint64_t)_mm256_extract_epi64(h3, 0);
    h[1][3] = (uint64_t)_mm256_extract_epi64(h3, 1);
    h[2][3] = (uint64_t)_mm256_extract_epi64(h3, 2);
    h[3][3] = (uint64_t)_mm256_extract_epi64(h3, 3);
    for (int l = 0; l < 4; l++) {
        store_u64le(outs[l] +  0, h[l][0]);
        store_u64le(outs[l] +  8, h[l][1]);
        store_u64le(outs[l] + 16, h[l][2]);
        store_u64le(outs[l] + 24, h[l][3]);
    }
}

/// Expose the x4 batch for testing (compared against 4× single-block).
void balloon_blake2b256_x4_test(
    const uint8_t *in0, const uint8_t *in1,
    const uint8_t *in2, const uint8_t *in3,
    uint8_t *out0, uint8_t *out1,
    uint8_t *out2, uint8_t *out3
) {
    blake2b256_x4_32byte(in0, in1, in2, in3, out0, out1, out2, out3);
}

int balloon_has_avx2_x4(void) { return 1; }

// Refill MIX_BATCH=4 ring entries starting at `ring[fill_off]`. Predicts the
// next 4 consumption states from the (*pred_c, *pred_r, *pred_i, *pred_j)
// cursor, hashes them in one AVX2 batch call, writes the resulting indices
// into the ring, and issues prefetches. Returns the number actually filled
// (< 4 near the end of the algorithm).
static int refill_ring_avx2(
    int *ring, int fill_off,
    uint64_t *pred_c, int *pred_r, int *pred_i, int *pred_j,
    int slots, int rounds, int delta,
    uint8_t *buf
) {
    uint8_t ins[4][32];
    int num = 0;
    for (int k = 0; k < 4; k++) {
        store_u64le(ins[k] +  0, *pred_c);
        store_u64le(ins[k] +  8, (uint64_t)*pred_r);
        store_u64le(ins[k] + 16, (uint64_t)*pred_i);
        store_u64le(ins[k] + 24, (uint64_t)*pred_j);
        num++;
        // Advance (*pred_c, *pred_r, *pred_i, *pred_j) to the NEXT consumption
        // state — i.e., the counter/position the subsequent mix-random will use.
        // Each mix-random increments counter by 1; each new slot additionally
        // consumes 1 more counter tick for its mix-previous.
        if (*pred_j + 1 < delta) {
            (*pred_c)++;
            (*pred_j)++;
        } else if (*pred_i + 1 < slots) {
            (*pred_c) += 2;
            (*pred_i)++;
            *pred_j = 0;
        } else if (*pred_r + 1 < rounds) {
            (*pred_c) += 2;
            (*pred_r)++;
            *pred_i = 0;
            *pred_j = 0;
        } else {
            break;  // past end — no more states to predict
        }
    }
    uint8_t outs[4][32];
    if (num == 4) {
        blake2b256_x4_32byte(ins[0], ins[1], ins[2], ins[3],
                             outs[0], outs[1], outs[2], outs[3]);
    } else {
        // Near end of algorithm — fall back to scalar single-block for the tail.
        for (int k = 0; k < num; k++) {
            blake2b256_single(ins[k], 32, outs[k]);
        }
    }
    for (int k = 0; k < num; k++) {
        int idx = (int)(load_u64le(outs[k]) % (uint64_t)slots);
        ring[fill_off + k] = idx;
        __builtin_prefetch(buf + (size_t)idx * 32, 0, 1);
    }
    return num;
}

#else // !BLAKE2B_X4_AVX2

// Stubs so the symbols resolve on non-AVX2 builds. Test callers should
// gate on balloon_has_avx2_x4(); the stubs just do 4× scalar so any
// accidental call still matches the reference.
void balloon_blake2b256_x4_test(
    const uint8_t *in0, const uint8_t *in1,
    const uint8_t *in2, const uint8_t *in3,
    uint8_t *out0, uint8_t *out1,
    uint8_t *out2, uint8_t *out3
) {
    blake2b256_single(in0, 32, out0);
    blake2b256_single(in1, 32, out1);
    blake2b256_single(in2, 32, out2);
    blake2b256_single(in3, 32, out3);
}

int balloon_has_avx2_x4(void) { return 0; }

#endif // BLAKE2B_X4_AVX2

// ---------------------------------------------------------------------------
// Prefetch-aware random index pre-computation
// ---------------------------------------------------------------------------

/// Compute the random neighbor index for a given slot without touching the buffer.
/// This is the "step 2a" of the mix phase — deterministic from (counter, round, i, j).
static inline int compute_random_idx(
    uint64_t counter, int round, int i, int j, int slots, uint8_t *scratch
) {
    store_u64le(scratch, counter);
    store_u64le(scratch + 8,  (uint64_t)round);
    store_u64le(scratch + 16, (uint64_t)i);
    store_u64le(scratch + 24, (uint64_t)j);
    uint8_t tmp[32];
    blake2b256_single(scratch, 32, tmp);
    return (int)(load_u64le(tmp) % (uint64_t)slots);
}

// ---------------------------------------------------------------------------
// BalloonHash with prefetching
// ---------------------------------------------------------------------------

int balloon_hash_fast(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    uint8_t *prefetch_inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
) {
    uint64_t counter = 0;

    // Phase 1: Expand — fills every slot sequentially
    store_u64le(inp, counter);
    int len = 8;
    memcpy(inp + len, password, (size_t)password_len); len += password_len;
    memcpy(inp + len, salt, (size_t)salt_len); len += salt_len;
    blake2b256_single(inp, len, buf);
    counter++;

    for (int i = 1; i < slots; i++) {
        if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
        store_u64le(inp, counter);
        copy32(buf + (i - 1) * 32, inp + 8);
        blake2b256_single(inp, 40, buf + i * 32);
        counter++;
    }

    // Phase 2: Mix.
#if BLAKE2B_X4_AVX2
    // 4-way batched path: pre-seed an 8-slot ring with the first 8 random
    // indices, then refill 4 at a time when a half drains. Every freshly-
    // filled index has ≥4 consumption-steps of lead time before it's used,
    // vs ~1 in the 1-ahead single-block pipeline — and the 4 compute_random_idx
    // hashes within a refill batch run in parallel through YMM lanes.
    (void)prefetch_inp;  // not used on this path
    {
        #define MIX_BATCH 4
        #define MIX_RING  (2 * MIX_BATCH)
        int ring[MIX_RING];
        int consume_pos = 0;

        // Prediction cursor: the (counter, round, i, j) the NEXT-to-be-computed
        // mix-random will use. Starts at (counter+1, 0, 0, 0) — matching the
        // seed state of the original 1-ahead pipeline.
        uint64_t pred_c = counter + 1;
        int pred_r = 0, pred_i = 0, pred_j = 0;

        // Pre-seed both halves before entering the main loop.
        refill_ring_avx2(ring, 0,
                         &pred_c, &pred_r, &pred_i, &pred_j,
                         slots, rounds, delta, buf);
        refill_ring_avx2(ring, MIX_BATCH,
                         &pred_c, &pred_r, &pred_i, &pred_j,
                         slots, rounds, delta, buf);

        for (int round = 0; round < rounds; round++) {
            for (int i = 0; i < slots; i++) {
                if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
                int off = i * 32;

                // Mix with previous neighbor (sequential — likely cached).
                store_u64le(inp, counter);
                copy32(buf + off, inp + 8);
                int prev = (i == 0) ? slots - 1 : i - 1;
                copy32(buf + prev * 32, inp + 40);
                blake2b256_single(inp, 72, buf + off);
                counter++;

                for (int j = 0; j < delta; j++) {
                    int idx = ring[consume_pos];
                    consume_pos = (consume_pos + 1) & (MIX_RING - 1);

                    // When consume_pos crosses a batch boundary, the half we
                    // just drained can be refilled with far-future indices.
                    // consume_pos ^ MIX_BATCH points at the drained half.
                    if ((consume_pos & (MIX_BATCH - 1)) == 0) {
                        int fill_off = consume_pos ^ MIX_BATCH;
                        refill_ring_avx2(ring, fill_off,
                                         &pred_c, &pred_r, &pred_i, &pred_j,
                                         slots, rounds, delta, buf);
                    }

                    // Mix with random neighbor.
                    store_u64le(inp, counter);
                    copy32(buf + off, inp + 8);
                    copy32(buf + (size_t)idx * 32, inp + 40);
                    blake2b256_single(inp, 72, buf + off);
                    counter++;
                }
            }
        }
        #undef MIX_BATCH
        #undef MIX_RING
    }
#else
    // Fallback: 1-ahead single-block pipeline (unchanged).
    {
        int next_idx = compute_random_idx(counter + 1, 0, 0, 0, slots, prefetch_inp);
        __builtin_prefetch(buf + (size_t)next_idx * 32, 0, 1);

        for (int round = 0; round < rounds; round++) {
            for (int i = 0; i < slots; i++) {
                if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
                int off = i * 32;

                // Step 1: mix with previous neighbor (sequential — likely cached).
                // During this BLAKE2b, the previously-issued prefetch loads data.
                store_u64le(inp, counter);
                copy32(buf + off, inp + 8);
                int prev = (i == 0) ? slots - 1 : i - 1;
                copy32(buf + prev * 32, inp + 40);
                blake2b256_single(inp, 72, buf + off);
                counter++;

                for (int j = 0; j < delta; j++) {
                    // Step 2: use the pre-computed random index (should be warm).
                    int idx = next_idx;

                    // Step 3: pipeline — pre-compute the NEXT random index now,
                    // before this slot's mix-random BLAKE2b. The prefetch gets
                    // the mix-random call + next mix-previous call as lead time.
                    if (j + 1 < delta) {
                        next_idx = compute_random_idx(counter + 1, round, i, j + 1,
                                                      slots, prefetch_inp);
                    } else if (i + 1 < slots) {
                        next_idx = compute_random_idx(counter + 2, round, i + 1, 0,
                                                      slots, prefetch_inp);
                    } else if (round + 1 < rounds) {
                        next_idx = compute_random_idx(counter + 2, round + 1, 0, 0,
                                                      slots, prefetch_inp);
                    }
                    __builtin_prefetch(buf + (size_t)next_idx * 32, 0, 1);

                    // Step 4: mix with random neighbor.
                    store_u64le(inp, counter);
                    copy32(buf + off, inp + 8);
                    copy32(buf + (size_t)idx * 32, inp + 40);
                    blake2b256_single(inp, 72, buf + off);
                    counter++;
                }
            }
        }
    }
#endif

    // Phase 3: Extract
    memcpy(output, buf + (size_t)(slots - 1) * 32, 32);
    return 0;
}

// Exposed for testing
void balloon_blake2b256_test(const uint8_t *input, int input_len, uint8_t *output) {
    blake2b256_single(input, input_len, output);
}

// ---------------------------------------------------------------------------
// Buffer allocation with huge page support
// ---------------------------------------------------------------------------

void *balloon_alloc_buffer(size_t size, int *used_hugepages) {
    *used_hugepages = 0;
#if defined(__linux__)
    // Flags (kernel-stable values; avoids requiring a specific glibc header):
    //   MAP_HUGETLB     = 0x40000
    //   MAP_HUGE_SHIFT  = 26 (bit position for huge-page size selector)
    //   MAP_HUGE_1GB    = 30 << MAP_HUGE_SHIFT
    //   MAP_HUGE_2MB    = 21 << MAP_HUGE_SHIFT  (default when no selector given)
    //
    // Try 1 GB huge pages first — a single TLB entry covers the whole 512 MB
    // scratchpad, so the random-access mix phase sees zero dTLB misses.
    // Requires root-reserved pages (hugepages-1G at boot or
    // /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages).
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | 0x40000 | (30 << 26),
                   -1, 0);
    if (p != MAP_FAILED) {
        *used_hugepages = 3; // explicit 1 GB huge pages
        return p;
    }
    // Try 2 MB huge pages (requires vm.nr_hugepages configuration, but more
    // commonly available than 1 GB).
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | 0x40000, -1, 0);
    if (p != MAP_FAILED) {
        *used_hugepages = 2; // explicit 2 MB huge pages
        return p;
    }
    // Fall back to regular pages with transparent huge page hint.
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        madvise(p, size, 14); // MADV_HUGEPAGE
        *used_hugepages = 1; // mmap with THP
        return p;
    }
#endif
    // Fall back to standard allocation
    return malloc(size);
}

void balloon_free_buffer(void *ptr, size_t size, int used_hugepages) {
#if defined(__linux__)
    if (used_hugepages > 0) {
        munmap(ptr, size);
        return;
    }
#endif
    (void)size;
    (void)used_hugepages;
    free(ptr);
}

// ---------------------------------------------------------------------------

// Simple BalloonHash — direct translation of the algorithm, no prefetch optimization.
int balloon_hash_simple(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
) {
    uint64_t counter = 0;

    // Phase 1: Expand
    store_u64le(inp, counter);
    int len = 8;
    memcpy(inp + len, password, (size_t)password_len); len += password_len;
    memcpy(inp + len, salt, (size_t)salt_len); len += salt_len;
    blake2b256_single(inp, len, buf);
    counter++;

    for (int i = 1; i < slots; i++) {
        if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
        store_u64le(inp, counter);
        copy32(buf + (i - 1) * 32, inp + 8);
        blake2b256_single(inp, 40, buf + i * 32);
        counter++;
    }

    // Phase 2: Mix — straight translation, no prefetch
    for (int round = 0; round < rounds; round++) {
        for (int i = 0; i < slots; i++) {
            if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
            int off = i * 32;

            store_u64le(inp, counter);
            copy32(buf + off, inp + 8);
            int prev = (i == 0) ? slots - 1 : i - 1;
            copy32(buf + prev * 32, inp + 40);
            blake2b256_single(inp, 72, buf + off);
            counter++;

            for (int j = 0; j < delta; j++) {
                store_u64le(inp, counter);
                store_u64le(inp + 8,  (uint64_t)round);
                store_u64le(inp + 16, (uint64_t)i);
                store_u64le(inp + 24, (uint64_t)j);
                uint8_t tmp[32];
                blake2b256_single(inp, 32, tmp);
                int idx = (int)(load_u64le(tmp) % (uint64_t)slots);

                store_u64le(inp, counter);
                copy32(buf + off, inp + 8);
                copy32(buf + (size_t)idx * 32, inp + 40);
                blake2b256_single(inp, 72, buf + off);
                counter++;
            }
        }
    }

    memcpy(output, buf + (size_t)(slots - 1) * 32, 32);
    return 0;
}
