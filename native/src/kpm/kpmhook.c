// SPDX-License-Identifier: GPL-2.0-or-later
// libkpmhook: LSPlant InitInfo inline_hooker/unhooker backed by the stealth KPM
// (shpte) over the no-superkey syscall bridge. See kpmhook.h for the contract.
//
// Per page we build ONE position-independent whole-page DBI clone (lib/dbi) and
// drive the KPM's multi-page `pghook` table: the first hook on a page arms it
// (UXN + clone + offmap), each later hook on the same page appends an override.
// `pgunhook` removes one override and disarms the page when its last one goes.
// The clone is a normal anonymous RX mmap (CRC-clean: the target .text is never
// modified; the clone is visible in /proc/maps -- the maps-hide hook covers that
// separately). Original execution is rerouted into the clone by the kernel fault
// router; the KPM only reads our offmap, never the clone bytes.

#include <android/log.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "dbi.h"
#include "kpmhook.h"

#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" -- matches kpm/shpte.c */
#ifndef __NR_personality
#define __NR_personality 92 /* arm64 asm-generic */
#endif

#define PAGE_SZ 0x1000UL
#define PAGE_INSN 1024              /* instructions in one 4 KiB page */
#define CLONE_CAP 6144             /* characterize: one fn (<=2048 insns) can expand ~5x */
#define MAX_RGN_PAGES 16           /* RV-2: must not exceed the KPM's MAX_RGN (covers all but a few huge fns) */
#define RGN_INSN_MAX (MAX_RGN_PAGES * PAGE_INSN) /* 16384 region source insns */
#define RGN_CLONE_CAP (RGN_INSN_MAX * 6)         /* clone scratch: ~5x expansion + headroom */
#define KPM_MAX_REGIONS 16         /* must not exceed the KPM's MAX_PG */
#define KPM_MAX_OV 8               /* must not exceed the KPM's MAX_OV */

struct ov {
    uint64_t off;   /* REGION-relative byte offset of the hooked entry */
    void *replace;  /* the hooker */
    void *backup;   /* in-clone faithful copy of the target */
};

/* RV-2: a clean-bounded MULTI-PAGE region [base, end) cloned in one piece, so a
 * function spanning a page boundary is wholly contained in the clone and RETs
 * normally. Offsets are region-relative. offmap is malloc'd (region-sized). */
struct rgn {
    int used;
    uint64_t base;            /* R_lo: region base page */
    uint64_t end;             /* R_hi: base + npages*0x1000 (exclusive, a clean boundary) */
    int npages;
    void *clone;              /* whole-region DBI clone (RX mmap) */
    size_t clone_sz;          /* mmap size (page-rounded) */
    uint32_t *offmap;         /* malloc'd, nmap entries (read by the KPM via access_process_vm) */
    int nmap;                 /* npages*1024 */
    struct ov ov[KPM_MAX_OV];
    int nov;                  /* live overrides in this region */
};

static struct rgn g_rgns[KPM_MAX_REGIONS];
static uint32_t g_clonebuf[CLONE_CAP]; /* characterize dbi scratch, reused under g_lock */
static uint32_t g_scratch_omap[CLONE_CAP]; /* characterize dbi offmap scratch, under g_lock */
/* static .bss buffer handed to the KPM's access_process_vm (reused under g_lock): the
 * KPM copies it into its own vmalloc immediately, so this need not persist. Scudo's
 * high mmap-region heap pages are NOT GUP-readable by access_process_vm (got=0), but a
 * .bss address is -- so the offmap to pass the KPM lives here, not on the malloc heap. */
static uint32_t g_pass_offmap[RGN_INSN_MAX];
static int g_pid = 0;
static int g_inited = 0;      /* 1 = bridge verified live + this process is gated-in */
static int g_init_failed = 0; /* 1 = gate rejected us or bridge was off (don't re-probe) */
static int g_force_enable = 0; /* standalone/test bypass of the process gate (NOT used by Vector) */
static int g_mode_read = 0;
static int g_characterize = 0; /* 1 = dry-run: log a span census, arm nothing */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#define KPM_LOG_TAG "kpmhook"

/* Process gate: engage the KPM backend only in the process named by the system
 * property `persist.kpmhook.target` (matched against /proc/self/cmdline), so that
 * system_server / zygote / every other injected process stay on pure Dobby. The
 * standalone test harness calls kpm_hook_force_enable() to bypass this (it has no
 * Dobby fallback and runs its own dedicated process). */
static int proc_is_target(void)
{
    if (g_force_enable) return 1;
    char cmd[256];
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t r = read(fd, cmd, sizeof(cmd) - 1);
    close(fd);
    if (r <= 0) return 0;
    cmd[r] = 0; /* args are NUL-separated; the first token is the process name */
#ifdef KPM_RV0_TARGET
    /* compile-time target: SELinux-proof (an untrusted_app cannot read a custom
     * persist.* prop on modern Android). Defined only for the RV-0 characterize build. */
    if (strcmp(cmd, KPM_RV0_TARGET) == 0) return 1;
#endif
    char target[PROP_VALUE_MAX];
    if (__system_property_get("persist.kpmhook.target", target) > 0 && strcmp(cmd, target) == 0)
        return 1;
    return 0;
}

/* Whether to run the dry-run census instead of arming hooks. The RV-0 build forces
 * it on at compile time (SELinux-proof -- an injected app cannot read a custom
 * persist.* prop); otherwise it is opt-in via persist.kpmhook.mode=characterize. */
static int is_characterize(void)
{
    if (!g_mode_read) {
#ifdef KPM_RV0_TARGET
        g_characterize = 1; /* RV-0 build: always dry-run -- arm nothing, just census */
#else
        char mode[PROP_VALUE_MAX];
        g_characterize =
            (__system_property_get("persist.kpmhook.mode", mode) > 0 && strcmp(mode, "characterize") == 0);
#endif
        g_mode_read = 1;
    }
    return g_characterize;
}

/* Instruction count from `entry` to the first RET / unconditional tail B (heuristic
 * function end -- enough for a page-span census). Bounded read to limit over-read
 * past the .text segment. */
static int fn_len_insns(uintptr_t entry)
{
    const uint32_t *p = (const uint32_t *)entry;
    const int cap = 2048; /* 8 KiB scan cap */
    for (int i = 0; i < cap; i++) {
        uint32_t w = p[i];
        if (w == 0xD65F03C0u) return i + 1;             /* RET */
        if ((w & 0xFC000000u) == 0x14000000u) return i + 1; /* unconditional B (tail) -- heuristic end */
    }
    return cap;
}

/* Dry-run census for one LSPlant target: how far the function reaches and whether it
 * spans page boundaries (the whole-page clone breaks on page-spanning funcs). Arms
 * nothing; logs one logcat line under tag "kpmhook". */
static void characterize_target(void *target)
{
    uintptr_t t = (uintptr_t)target;
    uint64_t page = (uint64_t)(t & ~(PAGE_SZ - 1));
    uint64_t off = (uint64_t)(t & (PAGE_SZ - 1));
    int len = fn_len_insns(t);
    uint64_t end = t + (uint64_t)len * 4;
    int pages = (int)((end - 1) / PAGE_SZ - t / PAGE_SZ + 1);
    int rc = dbi_recompile(t, (const uint32_t *)t, len + 4, g_clonebuf, CLONE_CAP, g_scratch_omap,
                           CLONE_CAP);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "census target=%p page=0x%lx off=0x%lx len=%d end=0x%lx pages=%d dbi_rc=%d%s",
                        target, (unsigned long)page, (unsigned long)off, len, (unsigned long)end,
                        pages, rc, pages > 1 ? " SPANS" : "");
}

/* Run a KPM command through the bridge. Fills `out` (NUL-terminated). Returns the
 * KPM rc. If the bridge is OFF this is a real personality() call: it would corrupt
 * the process personality, so callers must only use this after kpm_hook_init()
 * confirmed the bridge is armed. */
static long bridge_cmd(const char *cmd, char *out, size_t outlen)
{
    if (out && outlen) out[0] = 0;
    return syscall(__NR_personality, BRIDGE_MAGIC, cmd, (long)strlen(cmd) + 1, out, (long)outlen);
}

static int reply_ok(const char *out) { return out[0] == 'o' && out[1] == 'k'; }

/* Init under g_lock. Probe the bridge without corrupting personality if it's off:
 * query the current persona first; if our magic probe is swallowed by the KPM the
 * real syscall never runs (persona unchanged); if it is NOT swallowed (bridge off)
 * `out` stays empty and we restore the persona we clobbered. */
static int ensure_init_locked(void)
{
    if (g_inited) return 0;
    if (g_init_failed) return -1; /* gated out or bridge off -- don't re-probe/re-clobber personality */
    if (!proc_is_target()) {      /* process gate: only the named test process engages the KPM */
        g_init_failed = 1;
        return -1;
    }
    unsigned long orig = (unsigned long)syscall(__NR_personality, 0xffffffffUL); /* query only */
    char out[128];
    bridge_cmd("probe", out, sizeof out);
    if (out[0] == 0) {
        syscall(__NR_personality, orig); /* bridge off: undo the personality clobber */
        g_init_failed = 1;
        return -1;
    }
    g_pid = (int)getpid();
    g_inited = 1;
    return 0;
}

/* A page boundary `b` is clean if no function straddles it: the last word before b
 * is a RET / unconditional tail-B / padding (NOP/0). Conservative heuristic -- if it
 * misjudges "not clean" we just expand; if it wrongly judges "clean" the region would
 * cut a function, which the clean-boundary scan is designed to avoid. */
static int clean_boundary(uint64_t b)
{
    uint32_t w = ((const uint32_t *)(uintptr_t)b)[-1]; /* word at b-4 */
    if (w == 0xD65F03C0u) return 1;                  /* RET */
    if (w == 0xD503201Fu || w == 0) return 1;        /* NOP / zero padding */
    if ((w & 0xFC000000u) == 0x14000000u) return 1;  /* unconditional B (tail call) */
    return 0;
}

/* Region whose [base,end) contains `target`. Because end is always a clean boundary,
 * EVERY function starting in [base,end) also ends in it -- so a target found here is
 * fully contained and reuse is always safe (append override). */
static struct rgn *find_rgn_locked(uint64_t target)
{
    for (int i = 0; i < KPM_MAX_REGIONS; i++)
        if (g_rgns[i].used && target >= g_rgns[i].base && target < g_rgns[i].end) return &g_rgns[i];
    return 0;
}

/* lowest existing-region base in (base,cap), or 0 -- so make_rgn never expands into
 * (and overlaps) an already-armed region. */
static uint64_t next_rgn_base_locked(uint64_t base, uint64_t cap)
{
    uint64_t lo = 0;
    for (int i = 0; i < KPM_MAX_REGIONS; i++) {
        if (!g_rgns[i].used) continue;
        uint64_t rb = g_rgns[i].base;
        if (rb > base && rb < cap && (lo == 0 || rb < lo)) lo = rb;
    }
    return lo;
}

/* Build a clean-bounded multi-page region clone covering `target`. R_lo = target's
 * page; expand R_hi to the next clean boundary (capped at MAX_RGN_PAGES and at any
 * existing region). Returns a populated entry, or NULL -> caller falls back to Dobby. */
static struct rgn *make_rgn_locked(uint64_t target)
{
    uint64_t base = target & ~(PAGE_SZ - 1);
    uint64_t cap = base + (uint64_t)MAX_RGN_PAGES * PAGE_SZ;
    uint64_t collide = next_rgn_base_locked(base, cap);
    if (collide) cap = collide; /* don't overlap an existing region */
    uint64_t end = base + PAGE_SZ;
    while (end < cap && !clean_boundary(end)) end += PAGE_SZ;
    if (!clean_boundary(end)) return 0; /* no clean boundary in budget -> Dobby */

    int npages = (int)((end - base) / PAGE_SZ);
    int n = npages * PAGE_INSN;
    uint32_t *offmap = malloc((size_t)n * 4);
    uint32_t *scratch = malloc((size_t)RGN_CLONE_CAP * 4);
    if (!offmap || !scratch) { free(offmap); free(scratch); return 0; }

    /* bound LDR-literal pool reads to +/-8 MiB around the region (mapped segments) */
    int csz = dbi_recompile_range(base, (const uint32_t *)(uintptr_t)base, n, scratch, RGN_CLONE_CAP,
                                  offmap, n, (uintptr_t)(base - 0x800000), (uintptr_t)(end + 0x800000));
    if (csz < 0) { free(offmap); free(scratch); return 0; }

    size_t sz = ((size_t)csz * 4 + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1);
    void *clone = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) { free(offmap); free(scratch); return 0; }
    memcpy(clone, scratch, (size_t)csz * 4);
    free(scratch);
    __builtin___clear_cache((char *)clone, (char *)clone + sz);
    if (mprotect(clone, sz, PROT_READ | PROT_EXEC) != 0) { munmap(clone, sz); free(offmap); return 0; }

    struct rgn *e = 0;
    for (int i = 0; i < KPM_MAX_REGIONS; i++)
        if (!g_rgns[i].used) { e = &g_rgns[i]; break; }
    if (!e) { munmap(clone, sz); free(offmap); return 0; } /* registry full */
    e->base = base; e->end = end; e->npages = npages;
    e->clone = clone; e->clone_sz = sz;
    e->offmap = offmap; e->nmap = n;
    e->nov = 0; e->used = 1;
    return e;
}

static void add_ov_locked(struct rgn *e, uint64_t off, void *replace, void *backup)
{
    for (int i = 0; i < e->nov; i++)
        if (e->ov[i].off == off) { /* re-hook: update in place */
            e->ov[i].replace = replace;
            e->ov[i].backup = backup;
            return;
        }
    if (e->nov >= KPM_MAX_OV) return; /* KPM rejected too; backup still valid */
    e->ov[e->nov].off = off;
    e->ov[e->nov].replace = replace;
    e->ov[e->nov].backup = backup;
    e->nov++;
}

static void remove_ov_locked(struct rgn *e, uint64_t off)
{
    for (int i = 0; i < e->nov; i++)
        if (e->ov[i].off == off) {
            for (int j = i; j < e->nov - 1; j++) e->ov[j] = e->ov[j + 1];
            e->nov--;
            return;
        }
}

void kpm_hook_force_enable(void) { g_force_enable = 1; }

int kpm_hook_init(void)
{
    pthread_mutex_lock(&g_lock);
    int rc = ensure_init_locked();
    pthread_mutex_unlock(&g_lock);
    return rc;
}

void *kpm_inline_hooker(void *target, void *hooker)
{
    void *backup = 0;
    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) goto out;

    /* dry-run characterize mode: measure the function's page-span, arm nothing,
     * return NULL so the caller (Vector) falls back to Dobby and the app stays
     * functional. This is the crash-safe RV-0 path. */
    if (is_characterize()) {
        characterize_target(target);
        goto out;
    }

    uintptr_t t = (uintptr_t)target;
    struct rgn *e = find_rgn_locked(t); /* reuse the region if target is inside one (always fits) */
    if (!e) e = make_rgn_locked(t);
    if (!e) {
#ifdef KPM_DEBUG
        fprintf(stderr, "[kpm] make_rgn NULL for target=0x%lx\n", (unsigned long)t);
#endif
        goto out; /* >MAX_RGN_PAGES with no clean boundary, or alloc failure -> Dobby */
    }

    uint64_t roff = t - e->base; /* region-relative offset */
    backup = (char *)e->clone + (size_t)e->offmap[roff / 4] * 4;

    /* hand the KPM a .bss copy of the offmap (its heap original isn't GUP-readable) */
    memcpy(g_pass_offmap, e->offmap, (size_t)e->nmap * 4);

    char cmd[192], out[256];
    snprintf(cmd, sizeof cmd, "pghook %d 0x%lx 0x%lx 0x%lx %lu 0x%lx 0x%lx", g_pid,
             (unsigned long)e->base, (unsigned long)(uintptr_t)e->clone,
             (unsigned long)(uintptr_t)g_pass_offmap, (unsigned long)e->nmap, (unsigned long)roff,
             (unsigned long)(uintptr_t)hooker);
    bridge_cmd(cmd, out, sizeof out);
#ifdef KPM_DEBUG
    fprintf(stderr, "[kpm] rgn base=0x%lx npages=%d clone=%p nmap=%d roff=0x%lx cmd=[%s] reply=[%s]\n",
            (unsigned long)e->base, e->npages, e->clone, e->nmap, (unsigned long)roff, cmd, out);
#endif
    if (!reply_ok(out)) { backup = 0; goto out; }

    add_ov_locked(e, roff, hooker, backup);

out:
    pthread_mutex_unlock(&g_lock);
    return backup;
}

int kpm_inline_unhooker(void *func)
{
    int ok = 0;
    pthread_mutex_lock(&g_lock);
    if (!g_inited) goto out;

    uintptr_t f = (uintptr_t)func;
    struct rgn *e = find_rgn_locked(f);
    if (!e) goto out; /* not a KPM-hooked function -> caller uses Dobby */
    uint64_t roff = f - e->base; /* region-relative */

    char cmd[128], out[256];
    snprintf(cmd, sizeof cmd, "pgunhook %d 0x%lx 0x%lx", g_pid, (unsigned long)e->base,
             (unsigned long)roff);
    bridge_cmd(cmd, out, sizeof out);
    ok = reply_ok(out);
    if (ok) remove_ov_locked(e, roff); /* keep the clone/offmap until shutdown */

out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

void kpm_hook_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < KPM_MAX_REGIONS; i++) {
        if (!g_rgns[i].used) continue;
        if (g_rgns[i].clone) munmap(g_rgns[i].clone, g_rgns[i].clone_sz);
        free(g_rgns[i].offmap);
        memset(&g_rgns[i], 0, sizeof(g_rgns[i]));
    }
    pthread_mutex_unlock(&g_lock);
}
