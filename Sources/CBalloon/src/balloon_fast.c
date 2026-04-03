#include "balloon_fast.h"
#include <string.h>

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

#if defined(__x86_64__) || defined(_M_X64)
  #if defined(__SSSE3__)
    #include <tmmintrin.h>
    #define BLAKE2B_SSSE3 1
  #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
  #include <arm_neon.h>
  #define BLAKE2B_NEON 1
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

// Rotation constants for SSSE3 shuffle
static const __m128i rot16_shuf = {
    0x0504070601000302ULL, 0x0D0C0F0E09080B0AULL
};
static const __m128i rot24_shuf = {
    0x0407060500030201ULL, 0x0C0F0E0D080B0A09ULL
};

#define ROTR32(x)  _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))
#define ROTR24(x)  _mm_shuffle_epi8((x), rot24_shuf)
#define ROTR16(x)  _mm_shuffle_epi8((x), rot16_shuf)
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

#define G1N(r1,r2,r3,r4,b) \
    r1 = vaddq_u64(vaddq_u64(r1, b), r2); \
    r4 = veorq_u64(r4, r1); r4 = ROTR32(r4); \
    r3 = vaddq_u64(r3, r4); \
    r2 = veorq_u64(r2, r3); r2 = ROTR24(r2);

#define G2N(r1,r2,r3,r4,b) \
    r1 = vaddq_u64(vaddq_u64(r1, b), r2); \
    r4 = veorq_u64(r4, r1); r4 = ROTR16(r4); \
    r3 = vaddq_u64(r3, r4); \
    r2 = veorq_u64(r2, r3); r2 = ROTR63(r2);

#define DIAG_NEON(r1,r2,r3,r4) { \
    uint64x2_t t = r2; r2 = vextq_u64(r2, r2, 1); (void)t; \
    uint64x2_t t3 = r3; r3 = vextq_u64(r3, r3, 1); (void)t3; \
    uint64x2_t t4 = r4; r4 = vextq_u64(r4, r4, 1); (void)t4; \
}

// For NEON, use a simpler 2-register layout: each row = 1 uint64x2_t (2 lanes)
// This processes 2 G functions in parallel per row pair.
// Full 4-wide state: row1(v0,v1), row2(v4,v5), row3(v8,v9), row4(v12,v13) + similar for high half.

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    // State init
    uint64_t h[4] = { iv[0] ^ 0x01010020ULL, iv[1], iv[2], iv[3] };
    uint64_t v[16];
    v[0]=h[0]; v[1]=h[1]; v[2]=h[2]; v[3]=h[3];
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

    h[0] ^= v[0] ^ v[8];  h[1] ^= v[1] ^ v[9];
    h[2] ^= v[2] ^ v[10]; h[3] ^= v[3] ^ v[11];
    memcpy(output, h, 32);
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

    // Phase 2: Mix — with prefetching for random accesses
    for (int round = 0; round < rounds; round++) {
        // Pre-compute the random index for slot 0 and prefetch
        uint64_t base_counter = counter;
        int next_rand_idx = -1;
        {
            // Random index counter for slot 0 = base_counter + 0*3 + 1
            // But we need the counter AFTER step 1, so: base_counter + 1
            uint64_t rand_ctr = base_counter + 1;
            next_rand_idx = compute_random_idx(rand_ctr, round, 0, 0, slots, prefetch_inp);
            __builtin_prefetch(buf + (size_t)next_rand_idx * 32, 0, 0);
        }

        for (int i = 0; i < slots; i++) {
            if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;

            int rand_idx = next_rand_idx;

            // Step 1: hash(counter || buf[i] || buf[prev])
            int off = i * 32;
            store_u64le(inp, counter);
            copy32(buf + off, inp + 8);
            int prev = (i == 0) ? slots - 1 : i - 1;
            copy32(buf + prev * 32, inp + 40);
            blake2b256_single(inp, 72, buf + off);
            counter++;

            // Pre-compute random index for NEXT slot and prefetch
            // (gives ~2 BLAKE2b calls of lead time before the data is needed)
            if (i + 1 < slots) {
                // Random index counter for slot i+1:
                // After slot i: counter = base_counter + i*3 + 3
                // Step 2a of slot i+1 uses counter = base_counter + (i+1)*3 + 1
                uint64_t next_rand_ctr = base_counter + (uint64_t)(i + 1) * 3 + 1;
                next_rand_idx = compute_random_idx(
                    next_rand_ctr, round, i + 1, 0, slots, prefetch_inp
                );
                __builtin_prefetch(buf + (size_t)next_rand_idx * 32, 0, 0);
            }

            for (int j = 0; j < delta; j++) {
                // Step 2a: compute random index (reuse pre-computed for j=0)
                int idx;
                if (j == 0) {
                    idx = rand_idx;
                } else {
                    store_u64le(inp, counter);
                    store_u64le(inp + 8,  (uint64_t)round);
                    store_u64le(inp + 16, (uint64_t)i);
                    store_u64le(inp + 24, (uint64_t)j);
                    uint8_t tmp[32];
                    blake2b256_single(inp, 32, tmp);
                    idx = (int)(load_u64le(tmp) % (uint64_t)slots);
                }
                counter++;

                // Step 2b: hash(counter || buf[i] || buf[idx])
                store_u64le(inp, counter);
                copy32(buf + off, inp + 8);
                copy32(buf + (size_t)idx * 32, inp + 40);
                blake2b256_single(inp, 72, buf + off);
                counter++;
            }
        }
    }

    // Phase 3: Extract
    memcpy(output, buf + (size_t)(slots - 1) * 32, 32);
    return 0;
}
