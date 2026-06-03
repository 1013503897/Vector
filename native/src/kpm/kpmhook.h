/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libkpmhook: userspace glue that maps LSPlant's InitInfo inline-hook callbacks
 * onto the stealth KPM (shpte) via the no-superkey syscall bridge.
 *
 * kpm_inline_hooker(target, hooker) == LSPlant InlineHookFunType. It UXN-traps the
 * target's whole code page (multi-page `pghook` table), routes every instruction
 * on that page through a position-independent whole-page DBI clone (lib/dbi), and
 * overrides the target's entry -> hooker. The returned `backup` is the in-clone
 * faithful copy of the target -- call it to run the original. Several targets on
 * the SAME page share one trapped page / clone (the KPM appends overrides), which
 * is exactly what LSPlant needs (it inline-hooks ~20 libart funcs one at a time,
 * many sharing code pages).
 *
 * Prerequisite (privileged, done out-of-band once per boot by shctl + superkey):
 *     shctl <KEY> load shpte.kpm
 *     shctl <KEY> control shpte probe
 *     shctl <KEY> control shpte bridge
 * After that this library needs NO superkey -- it drives the KPM as the injected
 * agent (e.g. Vector's native layer) through personality(BRIDGE_MAGIC, ...).
 *
 * Boundary (Layer-1): the whole-page clone assumes the hooked function body fits
 * inside its page. Functions whose body spans a page boundary need multi-page
 * clones (tracked as future hardening); page-isolated targets are fine today.
 *
 * Build: link lib/dbi.c. Not for kernel use (plain userspace + libc + libdbi).
 */
#ifndef LIBKPMHOOK_H
#define LIBKPMHOOK_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bypass the process gate (persist.kpmhook.target). For standalone/test callers
 * (e.g. tools/kpmhooktool) that run in their own dedicated process and have no Dobby
 * fallback -- NOT used by Vector, which relies on the property gate for safety. Call
 * before kpm_hook_init() / the first kpm_inline_hooker().
 */
void kpm_hook_force_enable(void);

/*
 * Probe the bridge and cache getpid(). Returns 0 if this process is gated-in AND the
 * bridge is live; <0 otherwise (gated out, or bridge not armed) -- in which case no
 * hook is attempted. Optional: kpm_inline_hooker() lazily runs this on first use.
 */
int kpm_hook_init(void);

/* Release every whole-page clone mapping. Call after all unhooks are done. */
void kpm_hook_shutdown(void);

/* LSPlant InitInfo.inline_hooker: returns the backup (call-original) pointer, or
 * NULL on failure. `target` is the function to hook, `hooker` the replacement. */
void *kpm_inline_hooker(void *target, void *hooker);

/* LSPlant InitInfo.inline_unhooker: `func` is the original target previously
 * passed to kpm_inline_hooker. Returns 1 on success, 0 on failure. */
int kpm_inline_unhooker(void *func);

#ifdef __cplusplus
}
#endif

#endif /* LIBKPMHOOK_H */
