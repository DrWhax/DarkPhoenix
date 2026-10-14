// CPU AESE kernel for the encoded AES white-box. Same model as Shaders.metal.
#ifndef AESE_KERNEL_H
#define AESE_KERNEL_H

#include <stdint.h>

// fault_round < 0 means no fault. State is 16 bytes, in/out.
void aese_forward(
    const uint8_t *_Nonnull round_keys,
    const uint8_t *_Nonnull enc,
    const uint8_t *_Nonnull dec,
    const uint8_t *_Nonnull round_perm,
    const uint8_t *_Nonnull rev_perm,
    int nr,
    int encrypt,
    uint8_t *_Nonnull state,
    int fault_round,
    int fault_byte,
    int fault_xor);

// jobs is n records of 20 bytes: four little-endian words of state, then meta.
// meta low 16 bits are the fault round, or 0xFFFF for none; then byte, then xor.
void aese_eval_jobs(
    const uint8_t *_Nonnull round_keys,
    const uint8_t *_Nonnull enc,
    const uint8_t *_Nonnull dec,
    const uint8_t *_Nonnull round_perm,
    const uint8_t *_Nonnull rev_perm,
    int nr,
    int encrypt,
    const void *_Nonnull jobs,
    int n,
    uint8_t *_Nonnull out);

// plains: 16*256*16. fault_bytes: 16. out: 16*256*256*16, post-shifted attack view.
// fval 0 is an unfaulted encryption. It is not "xor 0", which would still encode and decode.
void aese_step2(
    const uint8_t *_Nonnull round_keys,
    const uint8_t *_Nonnull enc,
    const uint8_t *_Nonnull dec,
    const uint8_t *_Nonnull round_perm,
    const uint8_t *_Nonnull rev_perm,
    int nr,
    int encrypt,
    const uint8_t *_Nonnull plains,
    const uint8_t *_Nonnull fault_bytes,
    int fault_round,
    uint8_t *_Nonnull out);

// No-fault forward of counter blocks. Byte layout matches counterBlock in Oracle.swift.
void aese_counters(
    const uint8_t *_Nonnull round_keys,
    const uint8_t *_Nonnull enc,
    const uint8_t *_Nonnull dec,
    int nr,
    int encrypt,
    uint64_t base,
    int n,
    uint8_t *_Nonnull out);

#endif
