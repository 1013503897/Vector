/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libdbi: AArch64 position-independent function recompiler for the stealth-hook
 * agent. Extracted from the device-verified engines in tools/dbitarget3.c (ADR/
 * ADRP/B/BL + internal/conditional branches) and tools/dbitarget4.c (LDR-literal).
 *
 * Given a target function, it produces a clone that runs correctly at ANY address
 * (so it can be placed in a ghost page / userspace trampoline) plus an offset_map
 * (original-insn-index -> clone-insn-index) for the kernel do_page_fault router.
 *
 * IMPORTANT: recompilation must run in the SAME address space as the function --
 * it reads the LDR-literal pool and computes absolute external branch targets, so
 * those addresses must be valid where dbi_recompile() runs. This is exactly the
 * in-process LSPlant / injected-agent case.
 */
#ifndef LIBDBI_DBI_H
#define LIBDBI_DBI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    DBI_ERR_RANGE = -1,   /* clone would exceed out_cap */
    DBI_ERR_OFFMAP = -2,  /* function longer than offmap_cap */
    DBI_ERR_EMPTY = -3,   /* no instructions */
};

/*
 * Recompile the function whose first instruction is at runtime address `base`,
 * reading up to `src_max` source instructions from `src` (src[i] is the word at
 * base + i*4). Emits the position-independent clone into `out` (capacity
 * `out_cap` u32 words) and fills `offmap` (capacity `offmap_cap` entries) with
 * offmap[i] = clone instruction index for original instruction i (identity past
 * the function end). Stops after the first RET or tail B.
 *
 * Returns the clone size in instructions (>0) on success, or a negative DBI_ERR_*.
 */
int dbi_recompile(uintptr_t base, const uint32_t *src, int src_max, uint32_t *out, int out_cap,
                  uint32_t *offmap, int offmap_cap);

/*
 * Whole-page / arbitrary-range recompile: recompile ALL `n` instructions of
 * [base, base+n*4) (no stop at RET), so every function on a page is cloned and
 * the original page can be UXN-trapped while page-neighbors still run from the
 * clone. `lit_lo`/`lit_hi` bound LDR-literal pool reads (pass the readable source
 * range) so data words misdecoded as literal loads are not dereferenced. offmap[i]
 * = clone insn index of original insn i. Returns clone size in insns or DBI_ERR_*.
 */
int dbi_recompile_range(uintptr_t base, const uint32_t *src, int n, uint32_t *out, int out_cap,
                        uint32_t *offmap, int offmap_cap, uintptr_t lit_lo, uintptr_t lit_hi);

#ifdef __cplusplus
}
#endif

#endif /* LIBDBI_DBI_H */
