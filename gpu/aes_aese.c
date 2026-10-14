// CPU AESE kernel for the encoded AES white-box.
//
// AESE is AddRoundKey + SubBytes + ShiftRows. AESMC is MixColumns.
// That is exactly encRound. AESD is AddRoundKey + InvShiftRows + InvSubBytes,
// so a zero key is just the inverse S-box and shift. The round-key XOR stays
// explicit: fault injection needs the straightforward inverse at round boundaries,
// not the equivalent inverse cipher. AESIMC is InvMixColumns.
// Byte encodings stay table lookups. NEON tbl cannot index a 256-byte table.
//
// Step 2 shares the prefix up to the fault and the encode of that prefix.
// Only the faulted byte's decode changes across the 255 nonzero XOR values.

#include "aes_aese.h"

#include <arm_neon.h>
#include <string.h>

#if !defined(__aarch64__)
#error aese kernel requires arm64
#endif

typedef struct {
    uint32_t w0, w1, w2, w3, meta;
} AeseJob;

_Static_assert(sizeof(AeseJob) == 20, "Job stride must match Swift");

static const uint8_t k_inv_shift[16] __attribute__((aligned(16))) = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
};
static const uint8_t k_shift[16] __attribute__((aligned(16))) = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
};

static inline uint8x16_t load_rk(const uint8_t *rk, int r) {
    return vld1q_u8(rk + r * 16);
}

static inline uint8x16_t post_shift(uint8x16_t s, int encrypt) {
    uint8x16_t idx = vld1q_u8(encrypt ? k_inv_shift : k_shift);
    return vqtbl1q_u8(s, idx);
}

static inline uint8x16_t apply_tab(uint8x16_t s, const uint8_t *tab) {
    uint8_t b[16] __attribute__((aligned(16)));
    vst1q_u8(b, s);
#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) b[i] = tab[i * 256 + b[i]];
    return vld1q_u8(b);
}

// Interleaved LDRBs. Eight lanes hide L1 latency better than finishing one block.
static inline void tab8(uint8_t lane[8][16], const uint8_t *tab) {
#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        uint8_t t0 = tab[i * 256 + lane[0][i]];
        uint8_t t1 = tab[i * 256 + lane[1][i]];
        uint8_t t2 = tab[i * 256 + lane[2][i]];
        uint8_t t3 = tab[i * 256 + lane[3][i]];
        uint8_t t4 = tab[i * 256 + lane[4][i]];
        uint8_t t5 = tab[i * 256 + lane[5][i]];
        uint8_t t6 = tab[i * 256 + lane[6][i]];
        uint8_t t7 = tab[i * 256 + lane[7][i]];
        lane[0][i] = t0;
        lane[1][i] = t1;
        lane[2][i] = t2;
        lane[3][i] = t3;
        lane[4][i] = t4;
        lane[5][i] = t5;
        lane[6][i] = t6;
        lane[7][i] = t7;
    }
}

static inline void spill8(uint8_t lane[8][16],
                          uint8x16_t s0, uint8x16_t s1, uint8x16_t s2, uint8x16_t s3,
                          uint8x16_t s4, uint8x16_t s5, uint8x16_t s6, uint8x16_t s7) {
    vst1q_u8(lane[0], s0);
    vst1q_u8(lane[1], s1);
    vst1q_u8(lane[2], s2);
    vst1q_u8(lane[3], s3);
    vst1q_u8(lane[4], s4);
    vst1q_u8(lane[5], s5);
    vst1q_u8(lane[6], s6);
    vst1q_u8(lane[7], s7);
}

static inline void reload8(uint8_t lane[8][16],
                           uint8x16_t *s0, uint8x16_t *s1, uint8x16_t *s2, uint8x16_t *s3,
                           uint8x16_t *s4, uint8x16_t *s5, uint8x16_t *s6, uint8x16_t *s7) {
    *s0 = vld1q_u8(lane[0]);
    *s1 = vld1q_u8(lane[1]);
    *s2 = vld1q_u8(lane[2]);
    *s3 = vld1q_u8(lane[3]);
    *s4 = vld1q_u8(lane[4]);
    *s5 = vld1q_u8(lane[5]);
    *s6 = vld1q_u8(lane[6]);
    *s7 = vld1q_u8(lane[7]);
}

static inline void apply_tab8(uint8x16_t *s0, uint8x16_t *s1, uint8x16_t *s2, uint8x16_t *s3,
                              uint8x16_t *s4, uint8x16_t *s5, uint8x16_t *s6, uint8x16_t *s7,
                              const uint8_t *tab) {
    uint8_t lane[8][16] __attribute__((aligned(16)));
    spill8(lane, *s0, *s1, *s2, *s3, *s4, *s5, *s6, *s7);
    tab8(lane, tab);
    reload8(lane, s0, s1, s2, s3, s4, s5, s6, s7);
}

static inline void store8_raw(uint8_t *out,
                              uint8x16_t s0, uint8x16_t s1, uint8x16_t s2, uint8x16_t s3,
                              uint8x16_t s4, uint8x16_t s5, uint8x16_t s6, uint8x16_t s7) {
    vst1q_u8(out + 0 * 16, s0);
    vst1q_u8(out + 1 * 16, s1);
    vst1q_u8(out + 2 * 16, s2);
    vst1q_u8(out + 3 * 16, s3);
    vst1q_u8(out + 4 * 16, s4);
    vst1q_u8(out + 5 * 16, s5);
    vst1q_u8(out + 6 * 16, s6);
    vst1q_u8(out + 7 * 16, s7);
}

static inline void store8_view(uint8_t *dst, const uint8_t *out_tab, int encrypt,
                               uint8x16_t s0, uint8x16_t s1, uint8x16_t s2, uint8x16_t s3,
                               uint8x16_t s4, uint8x16_t s5, uint8x16_t s6, uint8x16_t s7) {
    apply_tab8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, out_tab);
    store8_raw(dst,
               post_shift(s0, encrypt), post_shift(s1, encrypt),
               post_shift(s2, encrypt), post_shift(s3, encrypt),
               post_shift(s4, encrypt), post_shift(s5, encrypt),
               post_shift(s6, encrypt), post_shift(s7, encrypt));
}

static inline void store1_view(uint8_t *dst, const uint8_t *out_tab, int encrypt, uint8x16_t s) {
    vst1q_u8(dst, post_shift(apply_tab(s, out_tab), encrypt));
}

static inline int job_fault(const AeseJob *j) {
    uint32_t raw = j->meta & 0xFFFFu;
    return raw == 0xFFFFu ? -1 : (int)raw;
}

static inline int enc_fault_pos(const uint8_t *rperm, int round, int fbyte) {
    if (round <= 0) return fbyte;
    return rperm[(round - 1) * 16 + fbyte];
}

static inline int dec_fault_pos(const uint8_t *revperm, int nr, int attack_round, int fbyte) {
    int aes_round = nr - 1 - attack_round;
    int enc_round = aes_round + 1;
    if (enc_round == nr) return fbyte;
    return revperm[aes_round * 16 + fbyte];
}

static inline uint8x16_t enc_tail1(uint8x16_t s, const uint8_t *rk, int r0, int nr) {
    if (r0 >= nr) return s;
    for (int r = r0; r < nr - 1; r++) {
        s = vaesmcq_u8(vaeseq_u8(s, load_rk(rk, r)));
    }
    return veorq_u8(vaeseq_u8(s, load_rk(rk, nr - 1)), load_rk(rk, nr));
}

// AESD is XOR, InvShiftRows, InvSubBytes — not InvShiftRows, InvSubBytes, XOR.
// A zero key makes it the inverse S-box/shift. The round-key XOR stays explicit so
// the state at round boundaries matches the straightforward inverse, which is where
// faults are injected.
static inline uint8x16_t dec_round1(uint8x16_t s, const uint8_t *rk, int aes_r, int nr) {
    uint8x16_t z = vdupq_n_u8(0);
    if (aes_r == nr - 1) {
        s = vaesdq_u8(s, load_rk(rk, nr));
        return veorq_u8(s, load_rk(rk, aes_r));
    }
    return veorq_u8(vaesdq_u8(vaesimcq_u8(s), z), load_rk(rk, aes_r));
}

static inline uint8x16_t dec_tail1(uint8x16_t s, const uint8_t *rk, int attack_round, int nr) {
    for (int ar = attack_round; ar < nr; ar++) {
        s = dec_round1(s, rk, nr - 1 - ar, nr);
    }
    return s;
}

static inline uint8x16_t prefix_enc(uint8x16_t s, const uint8_t *rk, int fault_round) {
    for (int r = 0; r < fault_round; r++) {
        s = vaesmcq_u8(vaeseq_u8(s, load_rk(rk, r)));
    }
    return s;
}

static inline uint8x16_t prefix_dec(uint8x16_t s, const uint8_t *rk, int fault_round, int nr) {
    for (int ar = 0; ar < fault_round; ar++) {
        s = dec_round1(s, rk, nr - 1 - ar, nr);
    }
    return s;
}

#define ENC_MIDDLE8(k)                      \
    do {                                    \
        s0 = vaesmcq_u8(vaeseq_u8(s0, k));  \
        s1 = vaesmcq_u8(vaeseq_u8(s1, k));  \
        s2 = vaesmcq_u8(vaeseq_u8(s2, k));  \
        s3 = vaesmcq_u8(vaeseq_u8(s3, k));  \
        s4 = vaesmcq_u8(vaeseq_u8(s4, k));  \
        s5 = vaesmcq_u8(vaeseq_u8(s5, k));  \
        s6 = vaesmcq_u8(vaeseq_u8(s6, k));  \
        s7 = vaesmcq_u8(vaeseq_u8(s7, k));  \
    } while (0)

#define ENC_LAST8(kL, kF)                            \
    do {                                             \
        s0 = veorq_u8(vaeseq_u8(s0, kL), kF);        \
        s1 = veorq_u8(vaeseq_u8(s1, kL), kF);        \
        s2 = veorq_u8(vaeseq_u8(s2, kL), kF);        \
        s3 = veorq_u8(vaeseq_u8(s3, kL), kF);        \
        s4 = veorq_u8(vaeseq_u8(s4, kL), kF);        \
        s5 = veorq_u8(vaeseq_u8(s5, kL), kF);        \
        s6 = veorq_u8(vaeseq_u8(s6, kL), kF);        \
        s7 = veorq_u8(vaeseq_u8(s7, kL), kF);        \
    } while (0)

#define DEC_NORMAL8(k)                                                      \
    do {                                                                    \
        uint8x16_t _z = vdupq_n_u8(0);                                      \
        s0 = veorq_u8(vaesdq_u8(vaesimcq_u8(s0), _z), k);                   \
        s1 = veorq_u8(vaesdq_u8(vaesimcq_u8(s1), _z), k);                   \
        s2 = veorq_u8(vaesdq_u8(vaesimcq_u8(s2), _z), k);                   \
        s3 = veorq_u8(vaesdq_u8(vaesimcq_u8(s3), _z), k);                   \
        s4 = veorq_u8(vaesdq_u8(vaesimcq_u8(s4), _z), k);                   \
        s5 = veorq_u8(vaesdq_u8(vaesimcq_u8(s5), _z), k);                   \
        s6 = veorq_u8(vaesdq_u8(vaesimcq_u8(s6), _z), k);                   \
        s7 = veorq_u8(vaesdq_u8(vaesimcq_u8(s7), _z), k);                   \
    } while (0)

#define DEC_SPECIAL8(kNr, kPrev)                         \
    do {                                                 \
        s0 = veorq_u8(vaesdq_u8(s0, kNr), kPrev);        \
        s1 = veorq_u8(vaesdq_u8(s1, kNr), kPrev);        \
        s2 = veorq_u8(vaesdq_u8(s2, kNr), kPrev);        \
        s3 = veorq_u8(vaesdq_u8(s3, kNr), kPrev);        \
        s4 = veorq_u8(vaesdq_u8(s4, kNr), kPrev);        \
        s5 = veorq_u8(vaesdq_u8(s5, kNr), kPrev);        \
        s6 = veorq_u8(vaesdq_u8(s6, kNr), kPrev);        \
        s7 = veorq_u8(vaesdq_u8(s7, kNr), kPrev);        \
    } while (0)

static void inject8(uint8x16_t *s0, uint8x16_t *s1, uint8x16_t *s2, uint8x16_t *s3,
                    uint8x16_t *s4, uint8x16_t *s5, uint8x16_t *s6, uint8x16_t *s7,
                    const uint8_t *enc_tab, const uint8_t *dec_tab,
                    const int pos[8], const uint8_t fx[8]) {
    uint8_t lane[8][16] __attribute__((aligned(16)));
    spill8(lane, *s0, *s1, *s2, *s3, *s4, *s5, *s6, *s7);
    tab8(lane, enc_tab);
    for (int L = 0; L < 8; L++) lane[L][pos[L]] ^= fx[L];
    tab8(lane, dec_tab);
    reload8(lane, s0, s1, s2, s3, s4, s5, s6, s7);
}

static void enc8(uint8x16_t s0, uint8x16_t s1, uint8x16_t s2, uint8x16_t s3,
                 uint8x16_t s4, uint8x16_t s5, uint8x16_t s6, uint8x16_t s7,
                 const uint8_t *rk, const uint8_t *enc, const uint8_t *dec,
                 int nr, int fr, const int pos[8], const uint8_t fx[8],
                 uint8_t *out) {
    apply_tab8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, dec);
    int pre = fr < 0 ? 0 : fr;
    for (int r = 0; r < pre; r++) {
        uint8x16_t k = load_rk(rk, r);
        ENC_MIDDLE8(k);
    }
    if (fr >= 0 && fr < nr) {
        inject8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7,
                enc + fr * 16 * 256, dec + fr * 16 * 256, pos, fx);
    }
    int r0 = fr < 0 ? 0 : fr;
    if (r0 < nr) {
        for (int r = r0; r < nr - 1; r++) {
            uint8x16_t k = load_rk(rk, r);
            ENC_MIDDLE8(k);
        }
        ENC_LAST8(load_rk(rk, nr - 1), load_rk(rk, nr));
    }
    apply_tab8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, enc + nr * 16 * 256);
    store8_raw(out, s0, s1, s2, s3, s4, s5, s6, s7);
}

static void dec8(uint8x16_t s0, uint8x16_t s1, uint8x16_t s2, uint8x16_t s3,
                 uint8x16_t s4, uint8x16_t s5, uint8x16_t s6, uint8x16_t s7,
                 const uint8_t *rk, const uint8_t *enc, const uint8_t *dec,
                 int nr, int fr, const int pos[8], const uint8_t fx[8],
                 uint8_t *out) {
    apply_tab8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, dec + nr * 16 * 256);
    int pre = fr < 0 ? 0 : fr;
    for (int ar = 0; ar < pre; ar++) {
        int aes_r = nr - 1 - ar;
        if (aes_r == nr - 1) {
            DEC_SPECIAL8(load_rk(rk, nr), load_rk(rk, aes_r));
        } else {
            DEC_NORMAL8(load_rk(rk, aes_r));
        }
    }
    if (fr >= 0 && fr < nr) {
        int aes_round = nr - 1 - fr;
        int enc_round = aes_round + 1;
        inject8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7,
                enc + enc_round * 16 * 256, dec + enc_round * 16 * 256, pos, fx);
    }
    int ar0 = fr < 0 ? 0 : fr;
    for (int ar = ar0; ar < nr; ar++) {
        int aes_r = nr - 1 - ar;
        if (aes_r == nr - 1) {
            DEC_SPECIAL8(load_rk(rk, nr), load_rk(rk, aes_r));
        } else {
            DEC_NORMAL8(load_rk(rk, aes_r));
        }
    }
    apply_tab8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, enc);
    store8_raw(out, s0, s1, s2, s3, s4, s5, s6, s7);
}

static void forward1(const uint8_t *rk, const uint8_t *enc, const uint8_t *dec,
                     const uint8_t *rperm, const uint8_t *revperm,
                     int nr, int encrypt, uint8_t *state, int fr, int fb, int fx) {
    uint8x16_t s = vld1q_u8(state);
    if (fr >= nr) fr = -1;
    if (encrypt) {
        s = apply_tab(s, dec);
        s = prefix_enc(s, rk, fr < 0 ? 0 : fr);
        if (fr >= 0) {
            uint8_t b[16];
            vst1q_u8(b, s);
            const uint8_t *et = enc + fr * 16 * 256;
            const uint8_t *dt = dec + fr * 16 * 256;
            for (int i = 0; i < 16; i++) b[i] = et[i * 256 + b[i]];
            b[enc_fault_pos(rperm, fr, fb)] ^= (uint8_t)fx;
            for (int i = 0; i < 16; i++) b[i] = dt[i * 256 + b[i]];
            s = vld1q_u8(b);
        }
        s = enc_tail1(s, rk, fr < 0 ? 0 : fr, nr);
        s = apply_tab(s, enc + nr * 16 * 256);
    } else {
        s = apply_tab(s, dec + nr * 16 * 256);
        s = prefix_dec(s, rk, fr < 0 ? 0 : fr, nr);
        if (fr >= 0) {
            int aes_round = nr - 1 - fr;
            int enc_round = aes_round + 1;
            uint8_t b[16];
            vst1q_u8(b, s);
            const uint8_t *et = enc + enc_round * 16 * 256;
            const uint8_t *dt = dec + enc_round * 16 * 256;
            for (int i = 0; i < 16; i++) b[i] = et[i * 256 + b[i]];
            b[dec_fault_pos(revperm, nr, fr, fb)] ^= (uint8_t)fx;
            for (int i = 0; i < 16; i++) b[i] = dt[i * 256 + b[i]];
            s = vld1q_u8(b);
        }
        s = dec_tail1(s, rk, fr < 0 ? 0 : fr, nr);
        s = apply_tab(s, enc);
    }
    vst1q_u8(state, s);
}

static void eval8(const uint8_t *rk, const uint8_t *enc, const uint8_t *dec,
                  const uint8_t *rperm, const uint8_t *revperm,
                  int nr, int encrypt, const AeseJob *jobs, int fr, uint8_t *out) {
    uint8x16_t s0 = vld1q_u8((const uint8_t *)&jobs[0]);
    uint8x16_t s1 = vld1q_u8((const uint8_t *)&jobs[1]);
    uint8x16_t s2 = vld1q_u8((const uint8_t *)&jobs[2]);
    uint8x16_t s3 = vld1q_u8((const uint8_t *)&jobs[3]);
    uint8x16_t s4 = vld1q_u8((const uint8_t *)&jobs[4]);
    uint8x16_t s5 = vld1q_u8((const uint8_t *)&jobs[5]);
    uint8x16_t s6 = vld1q_u8((const uint8_t *)&jobs[6]);
    uint8x16_t s7 = vld1q_u8((const uint8_t *)&jobs[7]);
    int pos[8];
    uint8_t fx[8];
    if (fr >= 0 && fr < nr) {
        for (int i = 0; i < 8; i++) {
            int fb = (int)((jobs[i].meta >> 16) & 0xFF);
            fx[i] = (uint8_t)(jobs[i].meta >> 24);
            pos[i] = encrypt ? enc_fault_pos(rperm, fr, fb) : dec_fault_pos(revperm, nr, fr, fb);
        }
    }
    if (encrypt) {
        enc8(s0, s1, s2, s3, s4, s5, s6, s7, rk, enc, dec, nr, fr, pos, fx, out);
    } else {
        dec8(s0, s1, s2, s3, s4, s5, s6, s7, rk, enc, dec, nr, fr, pos, fx, out);
    }
}

void aese_forward(const uint8_t *round_keys, const uint8_t *enc, const uint8_t *dec,
                  const uint8_t *round_perm, const uint8_t *rev_perm,
                  int nr, int encrypt, uint8_t *state,
                  int fault_round, int fault_byte, int fault_xor) {
    forward1(round_keys, enc, dec, round_perm, rev_perm, nr, encrypt, state,
             fault_round, fault_byte, fault_xor);
}

void aese_eval_jobs(const uint8_t *round_keys, const uint8_t *enc, const uint8_t *dec,
                    const uint8_t *round_perm, const uint8_t *rev_perm,
                    int nr, int encrypt, const void *jobs, int n, uint8_t *out) {
    if (n <= 0) return;
    const AeseJob *j = (const AeseJob *)jobs;
    int i = 0;
    while (i < n) {
        int fr = job_fault(&j[i]);
        if (fr >= nr) fr = -1;
        int run = 1;
        int limit = n - i;
        if (limit > 256) limit = 256;
        while (run < limit && job_fault(&j[i + run]) == fr) run++;
        int done = 0;
        for (; done + 8 <= run; done += 8) {
            eval8(round_keys, enc, dec, round_perm, rev_perm, nr, encrypt,
                  j + i + done, fr, out + (i + done) * 16);
        }
        for (; done < run; done++) {
            uint8_t block[16];
            memcpy(block, &j[i + done], 16);
            int fb = (int)((j[i + done].meta >> 16) & 0xFF);
            int fx = (int)(j[i + done].meta >> 24);
            forward1(round_keys, enc, dec, round_perm, rev_perm, nr, encrypt, block, fr, fb, fx);
            memcpy(out + (i + done) * 16, block, 16);
        }
        i += run;
    }
}

static uint8x16_t counter_at(uint64_t v) {
    uint8_t b[16] = {0};
    uint64_t be = __builtin_bswap64(v);
    memcpy(b + 8, &be, 8);
    return vld1q_u8(b);
}

void aese_counters(const uint8_t *round_keys, const uint8_t *enc, const uint8_t *dec,
                   int nr, int encrypt, uint64_t base, int n, uint8_t *out) {
    if (n <= 0) return;
    int pos[8] = {0};
    uint8_t fx[8] = {0};
    int i = 0;
    for (; i + 8 <= n; i += 8) {
        uint8x16_t s0 = counter_at(base + (uint64_t)i);
        uint8x16_t s1 = counter_at(base + (uint64_t)i + 1);
        uint8x16_t s2 = counter_at(base + (uint64_t)i + 2);
        uint8x16_t s3 = counter_at(base + (uint64_t)i + 3);
        uint8x16_t s4 = counter_at(base + (uint64_t)i + 4);
        uint8x16_t s5 = counter_at(base + (uint64_t)i + 5);
        uint8x16_t s6 = counter_at(base + (uint64_t)i + 6);
        uint8x16_t s7 = counter_at(base + (uint64_t)i + 7);
        if (encrypt) {
            enc8(s0, s1, s2, s3, s4, s5, s6, s7, round_keys, enc, dec, nr, -1, pos, fx, out + i * 16);
        } else {
            dec8(s0, s1, s2, s3, s4, s5, s6, s7, round_keys, enc, dec, nr, -1, pos, fx, out + i * 16);
        }
    }
    for (; i < n; i++) {
        uint8_t block[16] = {0};
        uint64_t be = __builtin_bswap64(base + (uint64_t)i);
        memcpy(block + 8, &be, 8);
        // No fault, so the permutation tables are not read.
        forward1(round_keys, enc, dec, enc, enc, nr, encrypt, block, -1, 0, 0);
        memcpy(out + i * 16, block, 16);
    }
}

static void load_faulted8(uint8x16_t *s0, uint8x16_t *s1, uint8x16_t *s2, uint8x16_t *s3,
                          uint8x16_t *s4, uint8x16_t *s5, uint8x16_t *s6, uint8x16_t *s7,
                          const uint8_t stable[16], int pos, const uint8_t *dpos,
                          uint8_t enc_pos, int f) {
    uint8_t lane[8][16] __attribute__((aligned(16)));
    for (int L = 0; L < 8; L++) {
        memcpy(lane[L], stable, 16);
        lane[L][pos] = dpos[enc_pos ^ (uint8_t)(f + L)];
    }
    reload8(lane, s0, s1, s2, s3, s4, s5, s6, s7);
}

static uint8x16_t load_faulted1(const uint8_t stable[16], int pos, const uint8_t *dpos,
                                uint8_t enc_pos, int f) {
    uint8_t b[16];
    memcpy(b, stable, 16);
    b[pos] = dpos[enc_pos ^ (uint8_t)f];
    return vld1q_u8(b);
}

// Encode the shared prefix once. Non-fault bytes decode once. fval 0 skips inject.
static void prepare_fault_bytes(uint8x16_t prefix, const uint8_t *enc_tab, const uint8_t *dec_tab,
                                int pos, uint8_t stable[16], uint8_t *enc_pos, const uint8_t **dpos) {
    uint8_t encb[16];
    vst1q_u8(encb, prefix);
    for (int i = 0; i < 16; i++) encb[i] = enc_tab[i * 256 + encb[i]];
    for (int i = 0; i < 16; i++) {
        stable[i] = (i == pos) ? 0 : dec_tab[i * 256 + encb[i]];
    }
    *enc_pos = encb[pos];
    *dpos = dec_tab + pos * 256;
}

static void step2_enc_fast(const uint8_t *rk, const uint8_t *in_tab, const uint8_t *out_tab,
                           const uint8_t *fault_enc, const uint8_t *fault_dec,
                           int nr, int fault_round, int tail, int pos,
                           const uint8_t *plain, uint8_t *dst) {
    uint8x16_t prefix = prefix_enc(apply_tab(vld1q_u8(plain), in_tab), rk, fault_round);
    store1_view(dst, out_tab, 1, enc_tail1(prefix, rk, fault_round, nr));

    uint8_t stable[16];
    uint8_t enc_pos = 0;
    const uint8_t *dpos = fault_dec;
    prepare_fault_bytes(prefix, fault_enc, fault_dec, pos, stable, &enc_pos, &dpos);

    uint8x16_t k0, kL, kF, kOnly;
    if (tail == 2) {
        k0 = load_rk(rk, fault_round);
        kL = load_rk(rk, nr - 1);
        kF = load_rk(rk, nr);
    } else {
        kOnly = load_rk(rk, nr - 1);
        kF = load_rk(rk, nr);
    }

    int f = 1;
    for (; f + 7 < 256; f += 8) {
        uint8x16_t s0, s1, s2, s3, s4, s5, s6, s7;
        load_faulted8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, stable, pos, dpos, enc_pos, f);
        if (tail == 2) {
            ENC_MIDDLE8(k0);
            ENC_LAST8(kL, kF);
        } else {
            ENC_LAST8(kOnly, kF);
        }
        store8_view(dst + f * 16, out_tab, 1, s0, s1, s2, s3, s4, s5, s6, s7);
    }
    for (; f < 256; f++) {
        uint8x16_t s = load_faulted1(stable, pos, dpos, enc_pos, f);
        s = enc_tail1(s, rk, fault_round, nr);
        store1_view(dst + f * 16, out_tab, 1, s);
    }
}

static void step2_dec_fast(const uint8_t *rk, const uint8_t *in_tab, const uint8_t *out_tab,
                           const uint8_t *fault_enc, const uint8_t *fault_dec,
                           int nr, int fault_round, int tail, int pos,
                           const uint8_t *plain, uint8_t *dst) {
    uint8x16_t prefix = prefix_dec(apply_tab(vld1q_u8(plain), in_tab), rk, fault_round, nr);
    store1_view(dst, out_tab, 0, dec_tail1(prefix, rk, fault_round, nr));

    uint8_t stable[16];
    uint8_t enc_pos = 0;
    const uint8_t *dpos = fault_dec;
    prepare_fault_bytes(prefix, fault_enc, fault_dec, pos, stable, &enc_pos, &dpos);

    // fault at nr-2: aes rounds 1 then 0, both normal. fault at nr-1: aes round 0 only.
    uint8x16_t kA = load_rk(rk, tail == 2 ? 1 : 0);
    uint8x16_t kB = load_rk(rk, 0);

    int f = 1;
    for (; f + 7 < 256; f += 8) {
        uint8x16_t s0, s1, s2, s3, s4, s5, s6, s7;
        load_faulted8(&s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, stable, pos, dpos, enc_pos, f);
        if (tail == 2) {
            DEC_NORMAL8(kA);
            DEC_NORMAL8(kB);
        } else {
            DEC_NORMAL8(kB);
        }
        store8_view(dst + f * 16, out_tab, 0, s0, s1, s2, s3, s4, s5, s6, s7);
    }
    for (; f < 256; f++) {
        uint8x16_t s = load_faulted1(stable, pos, dpos, enc_pos, f);
        s = dec_tail1(s, rk, fault_round, nr);
        store1_view(dst + f * 16, out_tab, 0, s);
    }
}

static void step2_generic(const uint8_t *rk, const uint8_t *in_tab, const uint8_t *out_tab,
                          const uint8_t *fault_enc, const uint8_t *fault_dec,
                          int nr, int encrypt, int fault_round, int pos,
                          const uint8_t *plain, uint8_t *dst) {
    uint8x16_t prefix = encrypt
        ? prefix_enc(apply_tab(vld1q_u8(plain), in_tab), rk, fault_round)
        : prefix_dec(apply_tab(vld1q_u8(plain), in_tab), rk, fault_round, nr);
    uint8x16_t z = encrypt ? enc_tail1(prefix, rk, fault_round, nr) : dec_tail1(prefix, rk, fault_round, nr);
    store1_view(dst, out_tab, encrypt, z);

    uint8_t stable[16];
    uint8_t enc_pos = 0;
    const uint8_t *dpos = fault_dec;
    prepare_fault_bytes(prefix, fault_enc, fault_dec, pos, stable, &enc_pos, &dpos);
    for (int f = 1; f < 256; f++) {
        uint8x16_t s = load_faulted1(stable, pos, dpos, enc_pos, f);
        s = encrypt ? enc_tail1(s, rk, fault_round, nr) : dec_tail1(s, rk, fault_round, nr);
        store1_view(dst + f * 16, out_tab, encrypt, s);
    }
}

void aese_step2(const uint8_t *round_keys, const uint8_t *enc, const uint8_t *dec,
                const uint8_t *round_perm, const uint8_t *rev_perm,
                int nr, int encrypt, const uint8_t *plains, const uint8_t *fault_bytes,
                int fault_round, uint8_t *out) {
    if (fault_round < 0 || fault_round >= nr) return;
    const uint8_t *in_tab;
    const uint8_t *out_tab;
    const uint8_t *fault_enc;
    const uint8_t *fault_dec;
    if (encrypt) {
        in_tab = dec;
        out_tab = enc + nr * 16 * 256;
        fault_enc = enc + fault_round * 16 * 256;
        fault_dec = dec + fault_round * 16 * 256;
    } else {
        int enc_round = nr - fault_round;
        in_tab = dec + nr * 16 * 256;
        out_tab = enc;
        fault_enc = enc + enc_round * 16 * 256;
        fault_dec = dec + enc_round * 16 * 256;
    }
    int tail = nr - fault_round;
    int fast = tail == 1 || tail == 2;
    for (int b = 0; b < 16; b++) {
        int fbyte = fault_bytes[b];
        int pos = encrypt ? enc_fault_pos(round_perm, fault_round, fbyte)
                          : dec_fault_pos(rev_perm, nr, fault_round, fbyte);
        for (int xi = 0; xi < 256; xi++) {
            const uint8_t *plain = plains + (b * 256 + xi) * 16;
            uint8_t *dst = out + ((b * 256 + xi) * 256) * 16;
            if (fast && encrypt) {
                step2_enc_fast(round_keys, in_tab, out_tab, fault_enc, fault_dec,
                               nr, fault_round, tail, pos, plain, dst);
            } else if (fast && !encrypt) {
                step2_dec_fast(round_keys, in_tab, out_tab, fault_enc, fault_dec,
                               nr, fault_round, tail, pos, plain, dst);
            } else {
                step2_generic(round_keys, in_tab, out_tab, fault_enc, fault_dec,
                              nr, encrypt, fault_round, pos, plain, dst);
            }
        }
    }
}
