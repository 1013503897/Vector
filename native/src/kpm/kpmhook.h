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
 * Rev1-(1): enable the ghost main-path. When on, every NEW region clone is hosted in
 * VMA-less kernel memory (KPM `pghookg`) instead of an anonymous RX mmap, so the
 * recompiled hook code is unreachable by /proc/maps + mincore enumeration (it stays
 * directly readable only if its VA is already known). Off by default -- the proven
 * userspace-clone path is unchanged until a caller opts in. Call before the first
 * kpm_inline_hooker(); affects regions created after the call. Requires the on-device
 * shpte KPM to be >= v0.6.2 (it understands `pghookg`); on an older KPM the pghookg
 * reply is not "ok", the hook returns NULL, and the caller falls back to Dobby.
 */
void kpm_hook_set_ghost(int on);

/*
 * Enable the kernel fs-hide for THIS process: register our tgid so the KPM spoofs its statfs
 * f_type (overlayfs -> erofs) and drops overlay/magisk lines from its /proc/self/mountinfo +
 * /proc/self/mounts -- defeats the "hidden overlayfs" mount detection. Reader-gated to our tgid
 * (root's own views stay truthful). Call once from postAppSpecialize. No-op on a pre-0.6.6 KPM.
 */
void kpm_hook_fshide_enable(void);

/*
 * Tell the KPM process gate the real package/process name. Vector calls this from
 * postAppSpecialize (where the app's nice_name is known) BEFORE LSPlant installs its
 * inline hooks -- at hook time /proc/self/cmdline is still "zygote64", so the backend
 * cannot identify the app on its own. Only the build's injection target then engages
 * the KPM (everything else stays on Dobby). Standalone test callers may skip this (the
 * gate falls back to /proc/self/cmdline). Call before kpm_hook_init() / the first hooker.
 */
void kpm_hook_set_process_name(const char *name);

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

/* LSPlant InitInfo.traceless_inline_hooker (Java methods only): SSOL-trap the cold
 * quick-compiled body `target` so a call routes to `hooker` and a call-original runs
 * the original via SSOL. Returns the unmapped backup VA, or NULL -> in-place fallback.
 * Distinct from kpm_inline_hooker: that clones hot libart-FUNCTION pages; SSOL on hot
 * .text would be a fault storm. See kpmhook.c for the split rationale. */
void *kpm_ssol_hooker(void *target, void *hooker);

/* Tear down one SSOL traceless hook installed by kpm_ssol_hooker. Returns 1/0. */
int kpm_ssol_unhooker(void *func);

#ifdef __cplusplus
}
#endif

#endif /* LIBKPMHOOK_H */
