#include <metal_stdlib>
using namespace metal;

// Encoded AES whitebox, matching darkphoenixAES fast fault injection.
// State is column-major: column c is bytes 4*c..4*c+3.

struct Job {
    uint w0, w1, w2, w3, meta;
};

struct EvalParams {
    uint nr;
    uint encrypt;
    uint nJobs;
};

struct Step1Params {
    uint nr;
    uint encrypt;
    uint doubleRS;
    uint count;
    uint baseLo;
    uint baseHi;
};

struct Step2Params {
    uint nr;
    uint encrypt;
    uint faultRound;
};

constant uchar RS[12] = {0, 1, 2, 3, 0, 2, 3, 1, 0, 3, 1, 2};
constant uchar kShift[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
constant uchar kInvShift[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};

void load_job(Job j, thread uchar s[16]) {
    uint w[4] = {j.w0, j.w1, j.w2, j.w3};
    for (int i = 0; i < 4; ++i) {
        s[i * 4 + 0] = (uchar)(w[i]);
        s[i * 4 + 1] = (uchar)(w[i] >> 8);
        s[i * 4 + 2] = (uchar)(w[i] >> 16);
        s[i * 4 + 3] = (uchar)(w[i] >> 24);
    }
}

void apply_tab(thread uchar s[16], device const uchar *tab, int round) {
    for (int i = 0; i < 16; ++i)
        s[i] = tab[(round * 16 + i) * 256 + s[i]];
}

void add_rk(thread uchar s[16], device const uchar *rk, int round) {
    device const uchar *k = rk + round * 16;
    for (int i = 0; i < 16; ++i) s[i] ^= k[i];
}

void sub_shift(thread uchar s[16], device const uchar *sbox) {
    uchar t[16];
    for (int i = 0; i < 16; ++i) t[i] = sbox[s[kShift[i]]];
    for (int i = 0; i < 16; ++i) s[i] = t[i];
}

void inv_sub_shift(thread uchar s[16], device const uchar *invsbox) {
    uchar t[16];
    for (int i = 0; i < 16; ++i) t[i] = s[kInvShift[i]];
    for (int i = 0; i < 16; ++i) s[i] = invsbox[t[i]];
}

void mix(thread uchar s[16], device const uchar *mul2, device const uchar *mul3) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uchar a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3];
        s[i] = mul2[a] ^ mul3[b] ^ d ^ e;
        s[i + 1] = a ^ mul2[b] ^ mul3[d] ^ e;
        s[i + 2] = a ^ b ^ mul2[d] ^ mul3[e];
        s[i + 3] = mul3[a] ^ b ^ d ^ mul2[e];
    }
}

void inv_mix(thread uchar s[16], device const uchar *m9, device const uchar *m11,
             device const uchar *m13, device const uchar *m14) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uchar a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3];
        uchar o0 = m14[a] ^ m11[b] ^ m13[d] ^ m9[e];
        uchar o1 = m9[a] ^ m14[b] ^ m11[d] ^ m13[e];
        uchar o2 = m13[a] ^ m9[b] ^ m14[d] ^ m11[e];
        uchar o3 = m11[a] ^ m13[b] ^ m9[d] ^ m14[e];
        s[i] = o0; s[i + 1] = o1; s[i + 2] = o2; s[i + 3] = o3;
    }
}

void fwd_shift(thread uchar s[16]) {
    uchar t[16];
    for (int i = 0; i < 16; ++i) t[i] = s[kShift[i]];
    for (int i = 0; i < 16; ++i) s[i] = t[i];
}

void inv_shift(thread uchar s[16]) {
    uchar t[16];
    for (int i = 0; i < 16; ++i) t[i] = s[kInvShift[i]];
    for (int i = 0; i < 16; ++i) s[i] = t[i];
}

void inject(thread uchar s[16], int attackRound, uchar fbyte, uchar fxor, uint encrypt, uint nr,
            device const uchar *enc, device const uchar *dec,
            device const uchar *rperm, device const uchar *revperm) {
    if (encrypt) {
        apply_tab(s, enc, attackRound);
        uchar pos = fbyte;
        if (attackRound != 0) pos = rperm[(attackRound - 1) * 16 + fbyte];
        s[pos] ^= fxor;
        apply_tab(s, dec, attackRound);
    } else {
        int aesRound = (int)nr - 1 - attackRound;
        int encRound = aesRound + 1;
        apply_tab(s, enc, encRound);
        uchar pos = fbyte;
        if (encRound != (int)nr) pos = revperm[aesRound * 16 + fbyte];
        s[pos] ^= fxor;
        apply_tab(s, dec, encRound);
    }
}

void enc_round(thread uchar s[16], int round, uint nr, device const uchar *rk,
               device const uchar *sbox, device const uchar *mul2, device const uchar *mul3) {
    add_rk(s, rk, round);
    if (round == (int)nr - 1) {
        sub_shift(s, sbox);
        add_rk(s, rk, (int)nr);
    } else {
        sub_shift(s, sbox);
        mix(s, mul2, mul3);
    }
}

void dec_round(thread uchar s[16], int round, uint nr, device const uchar *rk,
               device const uchar *invsbox, device const uchar *m9, device const uchar *m11,
               device const uchar *m13, device const uchar *m14) {
    if (round == (int)nr - 1) {
        add_rk(s, rk, (int)nr);
        inv_sub_shift(s, invsbox);
        add_rk(s, rk, round);
    } else {
        inv_mix(s, m9, m11, m13, m14);
        inv_sub_shift(s, invsbox);
        add_rk(s, rk, round);
    }
}

void wb_forward(thread uchar s[16], int faultRound, uchar fbyte, uchar fxor, uint encrypt, uint nr,
                device const uchar *rk, device const uchar *enc, device const uchar *dec,
                device const uchar *rperm, device const uchar *revperm,
                device const uchar *sbox, device const uchar *invsbox, device const uchar *mul) {
    device const uchar *mul2 = mul;
    device const uchar *mul3 = mul + 256;
    device const uchar *m9 = mul + 512;
    device const uchar *m11 = mul + 768;
    device const uchar *m13 = mul + 1024;
    device const uchar *m14 = mul + 1280;
    if (encrypt) {
        apply_tab(s, dec, 0);
        for (uint r = 0; r < nr; ++r) {
            if (faultRound == (int)r) inject(s, (int)r, fbyte, fxor, encrypt, nr, enc, dec, rperm, revperm);
            enc_round(s, (int)r, nr, rk, sbox, mul2, mul3);
        }
        apply_tab(s, enc, (int)nr);
    } else {
        apply_tab(s, dec, (int)nr);
        for (uint ar = 0; ar < nr; ++ar) {
            int aesR = (int)nr - 1 - (int)ar;
            if (faultRound == (int)ar) inject(s, (int)ar, fbyte, fxor, encrypt, nr, enc, dec, rperm, revperm);
            dec_round(s, aesR, nr, rk, invsbox, m9, m11, m13, m14);
        }
        apply_tab(s, enc, 0);
    }
}

void post_shift(thread uchar s[16], uint encrypt) {
    if (encrypt) inv_shift(s);
    else fwd_shift(s);
}

kernel void wb_eval(constant EvalParams &p [[buffer(0)]],
                    device const uchar *rk [[buffer(1)]],
                    device const uchar *enc [[buffer(2)]],
                    device const uchar *dec [[buffer(3)]],
                    device const uchar *rperm [[buffer(4)]],
                    device const uchar *revperm [[buffer(5)]],
                    device const uchar *sbox [[buffer(6)]],
                    device const uchar *invsbox [[buffer(7)]],
                    device const uchar *mul [[buffer(8)]],
                    device const Job *jobs [[buffer(9)]],
                    device uchar *out [[buffer(10)]],
                    uint gid [[thread_position_in_grid]]) {
    if (gid >= p.nJobs) return;
    Job j = jobs[gid];
    uchar s[16];
    load_job(j, s);
    uint fr = j.meta & 0xFFFFu;
    int faultRound = fr == 0xFFFFu ? -1 : (int)fr;
    uchar fbyte = (uchar)((j.meta >> 16) & 0xFF);
    uchar fxor = (uchar)((j.meta >> 24) & 0xFF);
    wb_forward(s, faultRound, fbyte, fxor, p.encrypt, p.nr, rk, enc, dec, rperm, revperm, sbox, invsbox, mul);
    for (int i = 0; i < 16; ++i) out[gid * 16 + i] = s[i];
}

bool claim_slot(device atomic_uint *flags, device uchar *inputs, uint slot, thread uchar inb[16]) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(flags + slot, &expected, 1u,
                                                  memory_order_relaxed, memory_order_relaxed)) {
            for (int i = 0; i < 16; ++i) inputs[slot * 16 + i] = inb[i];
            return true;
        }
        if (expected != 0) return false;
    }
    return false;
}

kernel void step1_search(constant Step1Params &p [[buffer(0)]],
                         device const uchar *rk [[buffer(1)]],
                         device const uchar *enc [[buffer(2)]],
                         device const uchar *dec [[buffer(3)]],
                         device const uchar *rperm [[buffer(4)]],
                         device const uchar *revperm [[buffer(5)]],
                         device const uchar *sbox [[buffer(6)]],
                         device const uchar *invsbox [[buffer(7)]],
                         device const uchar *mul [[buffer(8)]],
                         constant uchar *valueRef [[buffer(9)]],
                         device atomic_uint *flags [[buffer(10)]],
                         device uchar *inputs [[buffer(11)]],
                         uint gid [[thread_position_in_grid]]) {
    if (gid >= p.count) return;
    ulong v = ((ulong)p.baseHi << 32) | p.baseLo;
    v += gid;
    uchar inb[16];
    for (int i = 0; i < 16; ++i) inb[i] = 0;
    for (int i = 0; i < 8; ++i) inb[15 - i] = (uchar)(v >> (8 * i));
    uchar s[16];
    for (int i = 0; i < 16; ++i) s[i] = inb[i];
    wb_forward(s, -1, 0, 0, p.encrypt, p.nr, rk, enc, dec, rperm, revperm, sbox, invsbox, mul);
    post_shift(s, p.encrypt);

    for (int c = 0; c < 4; ++c) {
        for (int rs = 0; rs < 3; ++rs) {
            uchar a1 = RS[rs * 4 + 0];
            uchar a2 = RS[rs * 4 + 1];
            uchar b1 = RS[rs * 4 + 2];
            uchar b2 = RS[rs * 4 + 3];
            uchar ia1 = (uchar)(c * 4 + a1);
            uchar ia2 = (uchar)(c * 4 + a2);
            uchar ib1 = (uchar)(c * 4 + b1);
            uchar ib2 = (uchar)(c * 4 + b2);
            if (p.doubleRS) {
                if (s[ia1] == valueRef[ia1] && s[ia2] == valueRef[ia2]) {
                    claim_slot(flags, inputs, ((uint)ib1 * 3u + (uint)rs) * 256u + s[ib1], inb);
                    claim_slot(flags, inputs, ((uint)ib2 * 3u + (uint)rs) * 256u + s[ib2], inb);
                }
                if (s[ib1] == valueRef[ib1] && s[ib2] == valueRef[ib2]) {
                    claim_slot(flags, inputs, ((uint)ia1 * 3u + (uint)rs) * 256u + s[ia1], inb);
                    claim_slot(flags, inputs, ((uint)ia2 * 3u + (uint)rs) * 256u + s[ia2], inb);
                }
            } else {
                if (s[ia1] == valueRef[ia1]) claim_slot(flags, inputs, ((uint)ib1 * 3u + (uint)rs) * 256u + s[ib1], inb);
                if (s[ia2] == valueRef[ia2]) claim_slot(flags, inputs, ((uint)ib2 * 3u + (uint)rs) * 256u + s[ib2], inb);
                if (s[ib1] == valueRef[ib1]) claim_slot(flags, inputs, ((uint)ia1 * 3u + (uint)rs) * 256u + s[ia1], inb);
                if (s[ib2] == valueRef[ib2]) claim_slot(flags, inputs, ((uint)ia2 * 3u + (uint)rs) * 256u + s[ia2], inb);
            }
        }
    }
}

kernel void step2_eval(constant Step2Params &p [[buffer(0)]],
                       device const uchar *rk [[buffer(1)]],
                       device const uchar *enc [[buffer(2)]],
                       device const uchar *dec [[buffer(3)]],
                       device const uchar *rperm [[buffer(4)]],
                       device const uchar *revperm [[buffer(5)]],
                       device const uchar *sbox [[buffer(6)]],
                       device const uchar *invsbox [[buffer(7)]],
                       device const uchar *mul [[buffer(8)]],
                       device const uchar *plains [[buffer(9)]],
                       device const uchar *faultBytes [[buffer(10)]],
                       device uchar *out [[buffer(11)]],
                       uint gid [[thread_position_in_grid]]) {
    uint fval = gid & 255u;
    uint xi = (gid >> 8) & 255u;
    uint b = gid >> 16;
    if (b >= 16u) return;
    uchar s[16];
    device const uchar *src = plains + (b * 256u + xi) * 16u;
    for (int i = 0; i < 16; ++i) s[i] = src[i];
    int faultRound = fval == 0 ? -1 : (int)p.faultRound;
    uchar fbyte = faultBytes[b];
    uchar fxor = (uchar)fval;
    wb_forward(s, faultRound, fbyte, fxor, p.encrypt, p.nr, rk, enc, dec, rperm, revperm, sbox, invsbox, mul);
    post_shift(s, p.encrypt);
    for (int i = 0; i < 16; ++i) out[gid * 16 + i] = s[i];
}
