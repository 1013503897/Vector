/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Shared AArch64 instruction classifiers for the stealth-hook engines.
 *
 * The exact same PC-relative decoders were copy-pasted in THREE places -- lib/dbi.c
 * (the region-clone recompiler), lib/ssol.c (the offline SSOL simulator), and
 * kpm/shpte.c (the in-kernel SSOL simulator, ssol_-prefixed) -- and had begun to
 * DRIFT (notably the 128-bit SIMD LDR-literal handling). Consolidating them here
 * keeps all three consumers bit-identical: fix a classifier once, every engine sees it.
 *
 * Pure `static inline`, only <stdint.h>: no libc, no allocation, no globals -> safe in
 * the freestanding KPM build AND the userspace/offline builds. Consumers keep their own
 * ENCODE / emit / simulate logic; only the classify + immediate-extract math lives here.
 */
#ifndef LIB_AARCH64_DECODE_H
#define LIB_AARCH64_DECODE_H

#include <stdint.h>

/* sign-extend the low `bits` of v */
static inline int64_t a64_sext(int64_t v, int bits) { int s = 64 - bits; return (v << s) >> s; }

/* ---- classifiers ---- */
static inline int a64_is_adr(uint32_t i) { return (i & 0x9F000000u) == 0x10000000u; }
static inline int a64_is_adrp(uint32_t i) { return (i & 0x9F000000u) == 0x90000000u; }
static inline int a64_is_b(uint32_t i) { return (i & 0xFC000000u) == 0x14000000u; }
static inline int a64_is_bl(uint32_t i) { return (i & 0xFC000000u) == 0x94000000u; }
static inline int a64_is_bcond(uint32_t i) { return (i & 0xFF000010u) == 0x54000000u; }
static inline int a64_is_cbz(uint32_t i) { return (i & 0x7E000000u) == 0x34000000u; }   /* CBZ / CBNZ */
static inline int a64_is_tbz(uint32_t i) { return (i & 0x7E000000u) == 0x36000000u; }   /* TBZ / TBNZ */
/* LDR/LDRSW (literal), integer or SIMD, opc 00/01/10 (exclude PRFM opc=11) */
static inline int a64_is_ldrlit(uint32_t i) { return (i & 0x3B000000u) == 0x18000000u && ((i >> 30) & 3) != 3; }
/* plain register branches only; PAC variants (BRAA/BLRAA/RETAA...) set extra bits and DON'T match */
static inline int a64_is_br(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD61F0000u; }  /* BR  Xn */
static inline int a64_is_blr(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD63F0000u; } /* BLR Xn */
static inline int a64_is_ret(uint32_t i) { return (i & 0xFFFFFC1Fu) == 0xD65F0000u; } /* RET {Xn=30} */

/* absolute target for any immediate branch-ish insn at pc */
static inline uint64_t a64_btarget(uint32_t insn, uint64_t pc)
{
    if (a64_is_b(insn) || a64_is_bl(insn)) return pc + ((uint64_t)a64_sext(insn & 0x03ffffff, 26) << 2);
    if (a64_is_bcond(insn) || a64_is_cbz(insn)) return pc + ((uint64_t)a64_sext((insn >> 5) & 0x7ffff, 19) << 2);
    if (a64_is_tbz(insn)) return pc + ((uint64_t)a64_sext((insn >> 5) & 0x3fff, 14) << 2);
    return 0;
}

#endif /* LIB_AARCH64_DECODE_H */
