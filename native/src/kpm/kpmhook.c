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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <time.h> /* nanosleep / struct timespec (the B.7.1 table poll) */
#include <unistd.h>

#include "dbi.h"
#include "kpmhook.h"

/* Stringize an unquoted -D string define: Vector's build passes
 * -DINJECTED_PACKAGE_NAME=com.android.shell unquoted (see common/config.h VEC_STR). */
#define KPM_STR_(x) #x
#define KPM_STR(x) KPM_STR_(x)

/* Gate the KPM backend to the build's injection target UID. INJECTED_PACKAGE_UID is the
 * -D define Vector's build passes (com.android.shell -> 2000); fall back to 2000 when
 * this TU is built standalone without it (e.g. tools/kpmhooktool). */
#ifdef INJECTED_PACKAGE_UID
#define KPM_TARGET_UID INJECTED_PACKAGE_UID
#else
#define KPM_TARGET_UID 2000
#endif

#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" -- matches kpm/shpte.c */
/* Bridge carrier syscall = sysinfo (arm64 #179), NOT personality: Android's app
 * seccomp filter arg-filters personality() (blocks our magic arg with ERRNO), so the
 * personality bridge is unreachable from real zygote-forked app processes. sysinfo is
 * seccomp-allowed with arbitrary args and rarely called. Must match kpm/shpte.c BRIDGE_NR. */
#define BRIDGE_NR 179

#define PAGE_SZ 0x1000UL
#define PAGE_INSN 1024              /* instructions in one 4 KiB page */
#define CLONE_CAP 6144             /* characterize: one fn (<=2048 insns) can expand ~5x */
#define MAX_RGN_PAGES 64           /* RV-2: must not exceed the KPM's MAX_RGN (64: reach farther clean boundaries) */
#define RGN_INSN_MAX (MAX_RGN_PAGES * PAGE_INSN) /* 65536 region source insns */
#define RGN_CLONE_CAP (RGN_INSN_MAX * 6)         /* clone scratch: ~5x expansion + headroom */
#define KPM_MAX_REGIONS 16         /* must not exceed the KPM's MAX_PG */
#define KPM_MAX_OV 8               /* must not exceed the KPM's MAX_OV */
/* B.4: the KPM's VMA-less stub window (shpte.c WXSTUB_VA_BASE / WXSTUB_VA_PAGES). Every VA
 * allocator of ours must treat it as OCCUPIED: a published stub page has no VMA, so the maps
 * check in pick_ghost_va() cannot see it, and a ghost clone that landed on top would be refused
 * by the KPM (or, in the other order, refuse the stub). Keeping the windows disjoint by
 * construction removes that whole class of spurious fallbacks. */
#define WX_STUB_GHOST_BASE 0x5580000000UL
#define WX_STUB_GHOST_PAGES 64

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
    void *clone;              /* whole-region DBI clone: RX mmap (legacy) or RW source (ghost) */
    size_t clone_sz;          /* mmap size (page-rounded) */
    int clone_words;          /* DBI clone insn count (offmap targets index into this) */
    uint32_t *offmap;         /* malloc'd, nmap entries (read by the KPM via access_process_vm) */
    int nmap;                 /* npages*1024 */
    /* Rev1-(1): ghost main-path -- host the recompiled clone in VMA-less kernel memory
     * (pghookg) instead of an anon RX mmap, so it is unreachable by maps/mincore enumeration.
     * `clone` then stays a plain RW buffer the KPM copies from at arm; routing runs from
     * ghost_va. See kpm/shpte.c do_pghook (ghost path). */
    int ghost;                /* 1 = this region's clone lives at ghost_va (VMA-less) */
    uint64_t ghost_va;        /* chosen currently-unmapped VA for the ghost clone region */
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
static char g_proc_name[128];  /* real package/process name Vector passes via kpm_hook_set_process_name */
static int g_mode_read = 0;
static int g_characterize = 0; /* 1 = dry-run: log a span census, arm nothing */
/* Rev1-(1): ghost main-path toggle (kpm_hook_set_ghost). When on, every new region is
 * hosted in VMA-less kernel memory (pghookg) and no anon RX clone mmap is created. Off by
 * default so the proven userspace-clone path is unchanged until a caller opts in. */
static int g_ghost = 0;
static uint64_t g_ghost_cursor = 0; /* monotonic VA allocator for ghost regions (under g_lock) */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#define KPM_LOG_TAG "kpmhook"

/* Process gate: engage the KPM backend only in the build's injection target. The process
 * is identified by the name Vector hands us via kpm_hook_set_process_name() (the real
 * nice_name, known at postAppSpecialize) -- at LSPlant::Init/HookInline time
 * /proc/self/cmdline is still "zygote64", so it can't identify the app there. When no name
 * was passed (standalone harness, or the system_server path that never sets one), fall back
 * to /proc/self/cmdline. Match candidates: the build's INJECTED_PACKAGE_NAME / UID
 * (compile-time, SELinux-proof), the legacy KPM_TARGET / KPM_RV0_TARGET test targets, and
 * the runtime `persist.kpmhook.target` prop. Everything else (system_server / zygote / other
 * injected apps) stays on pure Dobby. kpm_hook_force_enable() bypasses the gate for the
 * standalone harness (no Dobby fallback, dedicated process). */
static int proc_is_target(void)
{
    if (g_force_enable) return 1;

    /* Prefer Vector's passed name; else fall back to /proc/self/cmdline. */
    char cmd[256];
    const char *name = g_proc_name;
    if (!name[0]) {
        int fd = open("/proc/self/cmdline", O_RDONLY);
        if (fd < 0) return 0;
        ssize_t r = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (r <= 0) return 0;
        cmd[r] = 0; /* args are NUL-separated; the first token is the process name */
        name = cmd;
    }

#ifdef KPM_TARGET_UID
    /* UID fallback: the injected host is UID-specialized at hook time even when no name was
     * passed (e.g. 2000 = the shell-UID parasitic LSPosed manager host). */
    if ((int)getuid() == KPM_TARGET_UID) return 1;
#endif
#ifdef INJECTED_PACKAGE_NAME
    /* the build's injection target (compile-time, SELinux-proof) */
    if (strcmp(name, KPM_STR(INJECTED_PACKAGE_NAME)) == 0) return 1;
#endif
#ifdef KPM_RV0_TARGET
    /* compile-time target: SELinux-proof (an untrusted_app cannot read a custom
     * persist.* prop on modern Android). Defined only for the RV-0 characterize build. */
    if (strcmp(name, KPM_RV0_TARGET) == 0) return 1;
#endif
#ifdef KPM_TARGET
    /* compile-time target for REAL hooking (no characterize) -- gate the KPM region
     * clones to this one process; system_server / everything else stays on Dobby. */
    if (strcmp(name, KPM_TARGET) == 0) return 1;
#endif
    char target[PROP_VALUE_MAX];
    if (__system_property_get("persist.kpmhook.target", target) > 0 && strcmp(name, target) == 0)
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

/* Run a KPM command through the bridge. Fills `out` (NUL-terminated). Returns the KPM
 * rc. If the bridge is OFF this is a real sysinfo() call with a bogus struct pointer
 * (BRIDGE_MAGIC) -> harmless EFAULT, no side effects (unlike personality, which would
 * have clobbered the process persona). */
static long bridge_cmd(const char *cmd, char *out, size_t outlen)
{
    if (out && outlen) out[0] = 0;
    return syscall(BRIDGE_NR, BRIDGE_MAGIC, cmd, (long)strlen(cmd) + 1, out, (long)outlen);
}

static int reply_ok(const char *out) { return out[0] == 'o' && out[1] == 'k'; }

/* Init under g_lock. Probe the bridge: if it is armed the KPM swallows our magic
 * sysinfo() and fills `out`; if not, the real sysinfo(BRIDGE_MAGIC,...) EFAULTs and
 * `out` stays empty (no cleanup needed). */
static int ensure_init_locked(void)
{
    if (g_inited) return 0;
    if (g_init_failed) return -1; /* gated out or bridge off -- don't re-probe */
    if (!proc_is_target()) {      /* process gate: only the named test process engages the KPM */
        g_init_failed = 1;
        return -1;
    }
    char out[128];
    bridge_cmd("probe", out, sizeof out);
    if (out[0] == 0) {
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

/* Bounds of the contiguous READABLE mapping containing `addr` (extends across adjacent
 * readable VMAs): returns the extent END, sets *out_start to the extent START, or 0 if
 * addr is not in a readable mapping. Two uses, both against hardened/packed libs (e.g.
 * GCash's libAPSE) that split their .text with non-readable --xp/---p sub-ranges:
 *   1. cap region expansion at [.,end) so dbi_recompile's [base,end) read stays readable;
 *   2. bound dbi's LDR-literal-pool reads to [start,end) so a bytecode word MISDECODED as
 *      an LDR-literal (obfuscated VM) resolving OUTSIDE the readable extent is SKIPPED, not
 *      read -- that out-of-extent read (e.g. base-486KB, below libAPSE) SIGSEGVs otherwise.
 * Reads /proc/self/maps (sleepable install context only, never the fault path); maps are
 * address-sorted. */
static uint64_t readable_extent(uint64_t addr, uint64_t *out_start)
{
    if (out_start) *out_start = 0;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[256];
    uint64_t start = 0, end = 0;
    while (fgets(line, sizeof line, f)) {
        uint64_t lo, hi;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3) continue;
        if (end == 0) {
            if (addr >= lo && addr < hi && perms[0] == 'r') { start = lo; end = hi; } /* containing readable VMA */
        } else if (lo == end && perms[0] == 'r') {
            end = hi;         /* extend across a contiguous readable VMA */
        } else if (lo >= end) {
            break;            /* gap or non-readable neighbor -> stop */
        }
    }
    fclose(f);
    if (out_start) *out_start = start;
    return end;
}

/* Rev1-(1): true if [va, va+sz) overlaps ANY current VMA in /proc/self/maps. Used to
 * validate a ghost-region VA candidate against live mappings (the KPM re-checks and falls
 * back on any residual collision). Conservative (returns "mapped") if maps can't be read. */
static int va_range_mapped(uint64_t va, size_t sz)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 1;
    char line[256];
    int hit = 0;
    uint64_t end = va + sz;
    while (fgets(line, sizeof line, f)) {
        uint64_t lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2) continue;
        if (va < hi && lo < end) { hit = 1; break; } /* ranges overlap */
    }
    fclose(f);
    return hit;
}

/* Rev1-(1): choose a currently-unmapped VA of `sz` bytes for a ghost clone region. Anchors
 * in the middle of the LARGEST /proc/self/maps gap on first use (a multi-GB hole on arm64,
 * far from anything the allocator hands out soon), then bumps a monotonic cursor so
 * successive ghost regions -- which are themselves VMA-less and thus invisible to a maps
 * re-scan -- never overlap each other. Verifies each candidate against live VMAs. Returns 0
 * if no gap is found (caller then arms the legacy userspace-clone path). Called under g_lock.
 * (§5 get_unmapped_area pinning would make this collision-proof; for Rev1 the KPM's unmapped
 * check + Dobby/userspace-clone fallback covers the rare race.) */
static uint64_t pick_ghost_va(size_t sz)
{
    sz = (sz + PAGE_SZ - 1) & ~(PAGE_SZ - 1);
    if (!g_ghost_cursor) {
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) return 0;
        char line[256];
        uint64_t prev_end = 0x100000, best_lo = 0, best_hi = 0;
        while (fgets(line, sizeof line, f)) {
            uint64_t lo, hi;
            if (sscanf(line, "%lx-%lx", &lo, &hi) != 2) continue;
            if (lo > prev_end && (lo - prev_end) > (best_hi - best_lo)) { best_lo = prev_end; best_hi = lo; }
            if (hi > prev_end) prev_end = hi;
        }
        fclose(f);
        if (best_hi - best_lo < (uint64_t)sz + 0x100000) return 0; /* no usable gap */
        g_ghost_cursor = (best_lo + (best_hi - best_lo) / 2) & ~(PAGE_SZ - 1);
    }
    for (int tries = 0; tries < 64; tries++) {
        uint64_t cand = g_ghost_cursor;
        g_ghost_cursor += sz + PAGE_SZ; /* advance past this region + a guard page */
        if (!cand) continue;
        /* B.4: the stub window is invisible to va_range_mapped (its pages have no VMA), so
         * reject it explicitly -- a clone sharing our stub pages would be refused by the KPM. */
        if (cand < WX_STUB_GHOST_BASE + (uint64_t)WX_STUB_GHOST_PAGES * PAGE_SZ &&
            WX_STUB_GHOST_BASE < cand + sz)
            continue;
        if (!va_range_mapped(cand, sz)) return cand;
    }
    return 0;
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
    /* never expand into a non-readable page: dbi_recompile reads [base,end) to build the
     * clone, and packed libs (libAPSE) split .text with non-readable sub-ranges -> a read
     * there SIGSEGVs (the flaky getColorInfo install crash). Cap at base's readable extent
     * and reuse the same [rd_start,rd_end) to bound dbi's literal-pool reads below. */
    uint64_t rd_start = 0;
    uint64_t rd_end = readable_extent(base, &rd_start);
    if (!rd_end) return 0;      /* base itself not readable -> Dobby (can't clone) */
    if (rd_end < cap) cap = rd_end;
    uint64_t end = base + PAGE_SZ;
    while (end < cap && !clean_boundary(end)) end += PAGE_SZ;
    if (!clean_boundary(end)) return 0; /* no clean boundary in budget -> Dobby */

    int npages = (int)((end - base) / PAGE_SZ);
    int n = npages * PAGE_INSN;
    uint32_t *offmap = malloc((size_t)n * 4);
    uint32_t *scratch = malloc((size_t)RGN_CLONE_CAP * 4);
    if (!offmap || !scratch) { free(offmap); free(scratch); return 0; }

    /* bound LDR-literal pool reads to base's READABLE extent (not a blind +/-8 MiB): an
     * obfuscated-VM word misdecoded as an LDR-literal that resolves outside [rd_start,rd_end)
     * is skipped instead of dereferenced (that out-of-extent read SIGSEGVs on packed libs). */
    int csz = dbi_recompile_range(base, (const uint32_t *)(uintptr_t)base, n, scratch, RGN_CLONE_CAP,
                                  offmap, n, (uintptr_t)rd_start, (uintptr_t)rd_end);
    if (csz < 0) { free(offmap); free(scratch); return 0; }

    size_t sz = ((size_t)csz * 4 + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1);
    void *clone = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) { free(offmap); free(scratch); return 0; }
    memcpy(clone, scratch, (size_t)csz * 4);
    free(scratch);
    /* ghost mode: leave the clone a plain RW buffer (GUP-readable source; the KPM copies it
     * into VMA-less kernel memory and does its own I-cache sync -- no anon RX mapping ever
     * exists). legacy mode: flip it to RX for in-place execution, as before. */
    if (!g_ghost) {
        __builtin___clear_cache((char *)clone, (char *)clone + sz);
        if (mprotect(clone, sz, PROT_READ | PROT_EXEC) != 0) { munmap(clone, sz); free(offmap); return 0; }
    }

    uint64_t ghost_va = 0;
    if (g_ghost) {
        ghost_va = pick_ghost_va(sz);
        if (!ghost_va) { munmap(clone, sz); free(offmap); return 0; } /* no VA -> caller falls back */
    }

    struct rgn *e = 0;
    for (int i = 0; i < KPM_MAX_REGIONS; i++)
        if (!g_rgns[i].used) { e = &g_rgns[i]; break; }
    if (!e) { munmap(clone, sz); free(offmap); return 0; } /* registry full */
    e->base = base; e->end = end; e->npages = npages;
    e->clone = clone; e->clone_sz = sz; e->clone_words = csz;
    e->offmap = offmap; e->nmap = n;
    e->ghost = g_ghost; e->ghost_va = ghost_va;
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

void kpm_hook_set_ghost(int on) { g_ghost = on ? 1 : 0; }

/* Enable the kernel fs-hide for THIS process: arm the statfs/mountinfo hooks and register our own
 * tgid in the KPM hide-set, so this app's statfs f_type reads overlayfs->erofs and its mountinfo/
 * mounts drop the overlay/magisk lines -- defeats the "hidden overlayfs" mount detection. Reader-
 * gated to our tgid only (root's own views stay truthful). Idempotent; call once from
 * postAppSpecialize (like set_ghost). No-op/harmless on a pre-0.6.6 KPM (reply != "ok"). */
void kpm_hook_fshide_enable(void)
{
    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) {
        pthread_mutex_unlock(&g_lock);
        return; /* gated out or bridge off -- nothing to do */
    }
    char cmd[64], out[256];
    bridge_cmd("fshide on", out, sizeof out);
    snprintf(cmd, sizeof cmd, "fshide add %d", g_pid);
    bridge_cmd(cmd, out, sizeof out);
    pthread_mutex_unlock(&g_lock);
}

void kpm_hook_set_process_name(const char *name)
{
    pthread_mutex_lock(&g_lock);
    if (name && name[0]) {
        strncpy(g_proc_name, name, sizeof(g_proc_name) - 1);
        g_proc_name[sizeof(g_proc_name) - 1] = 0;
    } else {
        g_proc_name[0] = 0;
    }
    pthread_mutex_unlock(&g_lock);
}

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
    /* backup = the in-clone faithful copy of the target. Legacy: inside the RX mmap.
     * Ghost: inside the VMA-less region at ghost_va (the KPM maps the same clone there). */
    uint64_t clone_base = e->ghost ? e->ghost_va : (uint64_t)(uintptr_t)e->clone;
    backup = (char *)(uintptr_t)(clone_base + (uint64_t)e->offmap[roff / 4] * 4);

    /* hand the KPM a .bss copy of the offmap (its heap original isn't GUP-readable) */
    memcpy(g_pass_offmap, e->offmap, (size_t)e->nmap * 4);

    char cmd[224], out[256];
    if (e->ghost)
        /* pghookg: clone hosted VMA-less at ghost_va; `clone` is the RW source, clone_words
         * its size (offmap targets index into it). See kpm/shpte.c do_pghook (ghost path). */
        snprintf(cmd, sizeof cmd, "pghookg %d 0x%lx 0x%lx 0x%lx %lu 0x%lx 0x%lx 0x%lx %lu", g_pid,
                 (unsigned long)e->base, (unsigned long)(uintptr_t)e->clone,
                 (unsigned long)(uintptr_t)g_pass_offmap, (unsigned long)e->nmap, (unsigned long)roff,
                 (unsigned long)(uintptr_t)hooker, (unsigned long)e->ghost_va,
                 (unsigned long)e->clone_words);
    else
        snprintf(cmd, sizeof cmd, "pghook %d 0x%lx 0x%lx 0x%lx %lu 0x%lx 0x%lx", g_pid,
                 (unsigned long)e->base, (unsigned long)(uintptr_t)e->clone,
                 (unsigned long)(uintptr_t)g_pass_offmap, (unsigned long)e->nmap, (unsigned long)roff,
                 (unsigned long)(uintptr_t)hooker);
    bridge_cmd(cmd, out, sizeof out);
#ifdef KPM_DEBUG
    fprintf(stderr, "[kpm] rgn base=0x%lx npages=%d clone=%p nmap=%d roff=0x%lx cmd=[%s] reply=[%s]\n",
            (unsigned long)e->base, e->npages, e->clone, e->nmap, (unsigned long)roff, cmd, out);
#endif
    if (!reply_ok(out)) {
        /* surface the KPM's exact reject reply to logcat (e.g. "error: ghost inject failed
         * rc=-6") -- the one diagnostic worth having when a device test can't be re-run cheaply */
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG, "hook reject: cmd=[%s] reply=[%s]", cmd, out);
        backup = 0;
        goto out;
    }

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

/* ===================== SSOL traceless-hook path (Java methods) =====================
 * The clone/pghook path above is for HOT libart-FUNCTION inline hooks (HookInline): it
 * reroutes the whole page to a clone that runs natively at full speed -- right for hot
 * code, but WRONG for the cold Java-method `qc` traceless hooks (traceless_inline_hooker),
 * where on dense framework JIT the clone corrupts (code/data interleaving + clone return
 * addresses -> SIGILL/SIGSEGV). SSOL runs the ORIGINAL qc at its original address (the KPM
 * UXN-traps the qc page and simulates / single-steps each insn), so it is correct on
 * complex apps -- at the cost of a fault per executed insn on the trapped page. That is
 * fine for a COLD qc (only runs via the hook / call-original) but would be catastrophic on
 * HOT libart .text (a fault storm; observed: SIGTRAP). Hence a SEPARATE table + entry
 * points from the clone path: kpm_inline_hooker stays clone (libart funcs), this is SSOL.
 *
 * Two pools of UNMAPPED high user VAs (must not collide with a real mapping; high VAs are
 * normally free on this arm64 layout -- the KPM self-test used the same range):
 *   xol_va = SSOL_XOL_BASE + region_index * PAGE_SZ                  (one scratch page/region)
 *   bk_va  = SSOL_BK_BASE  + (region_index*SSOL_MAX_OV + slot)*PAGE  (unique backup VA/hook) */
#define SSOL_MAX_REGIONS 16 /* must not exceed the KPM's MAX_SSOL_RGN (16) */
#define SSOL_MAX_OV 16      /* hooked qc per region; must not exceed the KPM's MAX_SSOL_OV (16) */
#define SSOL_BK_BASE 0x5500000000ULL
#define SSOL_XOL_BASE 0x5540000000ULL

struct sov {
    int used;
    uint64_t off;   /* page-relative offset of the hooked qc entry (qc - base) */
    void *replace;  /* the LSPlant trampoline */
    uint64_t bk_va; /* unique unmapped backup VA handed back to LSPlant */
};
struct srgn {
    int used;
    uint64_t base;   /* qc's code page (qc & ~0xfff); the KPM UXN-traps exactly this 1 page */
    uint64_t xol_va; /* per-region XOL scratch page VA (unmapped) */
    struct sov ov[SSOL_MAX_OV];
};
static struct srgn g_srgns[SSOL_MAX_REGIONS];

/* SSOL region whose trapped page (== base) contains `target` (each region traps one page,
 * so several qc on that page share it). */
static struct srgn *find_srgn_locked(uint64_t target)
{
    uint64_t page = target & ~(PAGE_SZ - 1);
    for (int i = 0; i < SSOL_MAX_REGIONS; i++)
        if (g_srgns[i].used && g_srgns[i].base == page) return &g_srgns[i];
    return 0;
}
static struct srgn *make_srgn_locked(uint64_t target)
{
    int idx = -1;
    for (int i = 0; i < SSOL_MAX_REGIONS; i++)
        if (!g_srgns[i].used) { idx = i; break; }
    if (idx < 0) return 0; /* table full -> in-place fallback */
    struct srgn *e = &g_srgns[idx];
    memset(e, 0, sizeof(*e));
    e->base = target & ~(PAGE_SZ - 1);
    e->xol_va = SSOL_XOL_BASE + (uint64_t)idx * PAGE_SZ;
    e->used = 1;
    return e;
}

/* LSPlant InitInfo.traceless_inline_hooker: SSOL-trap the Java method `qc` (cold) so a real
 * call routes to `hooker` (the trampoline) and a call-original runs the body via SSOL.
 * Returns the unmapped backup VA (bk_va, set by LSPlant as the backup-ArtMethod entry), or
 * NULL -> caller falls back to the in-place ArtMethod swap. NOT for libart-function hooks --
 * those stay on the clone via kpm_inline_hooker (SSOL on hot .text is a fault storm). */
void *kpm_ssol_hooker(void *target, void *hooker)
{
    uint64_t bk = 0;
    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) goto out;

    uintptr_t t = (uintptr_t)target;
    struct srgn *e = find_srgn_locked(t); /* same-page qc share one trapped region */
    if (!e) e = make_srgn_locked(t);
    if (!e) goto out; /* region table full -> in-place fallback */
    int ri = (int)(e - g_srgns);
    uint64_t off = t - e->base; /* page-relative entry offset */

    /* find this qc's existing ov slot (re-hook) or claim a free one. bk_va is derived from
     * (region, slot) so it is unique + stable across re-hooks. */
    int k = -1, freek = -1;
    for (int i = 0; i < SSOL_MAX_OV; i++) {
        if (e->ov[i].used && e->ov[i].off == off) { k = i; break; }
        if (freek < 0 && !e->ov[i].used) freek = i;
    }
    if (k < 0) k = freek;
    if (k < 0) goto out; /* ov table full -> in-place fallback */
    uint64_t bkva = SSOL_BK_BASE + ((uint64_t)ri * SSOL_MAX_OV + (uint64_t)k) * PAGE_SZ;

    /* ssolhook <pid> <region_base> <npages=1> <xol_va> <entry=qc> <replace=trampoline> <backup=bk_va> */
    char cmd[192], out[256];
    snprintf(cmd, sizeof cmd, "ssolhook %d 0x%lx 1 0x%lx 0x%lx 0x%lx 0x%lx", g_pid,
             (unsigned long)e->base, (unsigned long)e->xol_va, (unsigned long)t,
             (unsigned long)(uintptr_t)hooker, (unsigned long)bkva);
    bridge_cmd(cmd, out, sizeof out);
    if (!reply_ok(out)) {
        int any = 0;
        for (int i = 0; i < SSOL_MAX_OV; i++)
            if (e->ov[i].used) { any = 1; break; }
        if (!any) e->used = 0; /* release a freshly-made-but-unused region */
        goto out;
    }
    e->ov[k].used = 1;
    e->ov[k].off = off;
    e->ov[k].replace = hooker;
    e->ov[k].bk_va = bkva;
    bk = bkva;

out:
    pthread_mutex_unlock(&g_lock);
    return (void *)(uintptr_t)bk;
}

int kpm_ssol_unhooker(void *func)
{
    int ok = 0;
    pthread_mutex_lock(&g_lock);
    if (!g_inited) goto out;
    uintptr_t f = (uintptr_t)func;
    struct srgn *e = find_srgn_locked(f);
    if (!e) goto out;
    uint64_t off = f - e->base;
    int k = -1;
    for (int i = 0; i < SSOL_MAX_OV; i++)
        if (e->ov[i].used && e->ov[i].off == off) { k = i; break; }
    if (k < 0) goto out;
    char cmd[128], out[256];
    snprintf(cmd, sizeof cmd, "ssolunhook %d 0x%lx 0x%lx", g_pid, (unsigned long)e->base,
             (unsigned long)f);
    bridge_cmd(cmd, out, sizeof out);
    ok = reply_ok(out);
    if (ok) {
        e->ov[k].used = 0;
        int any = 0;
        for (int i = 0; i < SSOL_MAX_OV; i++)
            if (e->ov[i].used) { any = 1; break; }
        if (!any) e->used = 0; /* KPM disarmed the region on the last ov */
    }
out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

/* ===================== R^X shadow-page traceless hook path (Java methods, Phase B.2) =========
 *
 * WHY THIS EXISTS (and why the other two Java backends were abandoned -- see
 * xp_on_demo/FINDINGS-java-traceless.md §3):
 *   - SSOL traps the qc page with PTE_UXN and simulates each instruction: 100% SIGSEGV on a
 *     real app (a reference-width slot in ART's stack got written with a small integer).
 *   - The region CLONE reroutes the page into a recompiled copy: on the first ART stack walk
 *     (e.g. loading the module entry class) the unwinder aborts with
 *     `Check failed: stack_map->IsValid() StackMap not found for <clone PC>`.
 * Both change WHERE the original code runs. This backend does not: the original code keeps
 * running at its own address, on its own PC, with its own ArtMethod -- only the *physical*
 * page behind that VA differs, and only for execution.
 *
 * The KPM (shpte.c, WX: section) keeps TWO physical pages behind the user VA:
 *   execute -> the SHADOW copy (patched bytes), AP[1]=0 (no EL0 data access) -> "--x"
 *   read    -> the pristine ORIGINAL page, AP[2]=1, UXN=1                      -> "r--"
 * and flips between them from the fault path. So a reader (memcmp / CRC / /proc/pid/mem) sees
 * the ORIGINAL bytes, while execution runs `movz x16,#lo; movk x16,#mid,lsl 16;
 * movk x16,#hi,lsl 32; br x16` in place of the method's first 4 instructions.
 *
 * PHASE B.6 -- THE SELF-READING CASE GETS A THIRD MODE. That flip livelocks if the method's own
 * body reads its own page (the read fault flips to "r--", the retry's fetch is refused by UXN,
 * flipping back re-arms the read fault, forever -- B.1 device-measured). JIT bodies almost always
 * load constants from their own page, so refusing them (the pre-B.6 behaviour) pushed most
 * candidates onto the detectable in-place entry swap. A body that reads its own page is now
 * armed WX_MODE_RX instead: ONE resident readable+executable SHADOW (see the WX_MODE_* block
 * below for the definition) that never flips, so there is no fault to livelock on. The price is
 * that this page gives up read-hiding: the patched 16 bytes read back AS THE PATCH, both from
 * the target and from /proc/pid/mem. Accepted because the rest of the shadow page is
 * byte-identical to the original, and the pages that need this are JIT pages whose contents a
 * recompile replaces anyway. The rule is unchanged: RX is chosen ONLY on the evidence of
 * wx_body_reads_own_page(), never to make an arm succeed (red line 1).
 *
 * NO KERNEL CHANGE: wx_apply classifies every call as WX_CTX_ADMIN, whose flush is
 * sync_icache(kaddr_shadow) (a KERNEL alias -- legal in any context) + `ic ialluis` (takes no
 * VA). Both are correct when the target process arms its own page, so wxpatch is used as-is.
 *
 * RED LINE 1 -- NOTHING WE WRITE MAY DO A DATA ACCESS TO THE PATCHED PAGE:
 * while the exec view is live the page is execute-only, so a data access to it permission-
 * faults; before_pf flips to the read view, the retry's INSTRUCTION FETCH then faults (the
 * read view is UXN), and if the faulting instruction itself lives on that page the two faults
 * alternate forever (device-measured 1:1, ESR 0x9200000f / 0x8200000f). That is why the patch
 * is movz/movk (zero memory access) and why the call-original STUB below is a separate,
 * ordinary RWX page that we own: the stub must not read the patched page either.
 * (Phase B.6 relaxes this for the TARGET's own body, and only there: a body that does read its
 * own page is armed WX_MODE_RX, whose resident r-x shadow cannot fault at all. Our own emitted
 * code is still bound by the rule above -- the patch and the stub keep their zero-access
 * property, because under RX a read would merely work; the reason not to depend on that is
 * that RX costs read-hiding, so nothing of ours may force a page into it.)
 *
 * RED LINE 3 -- THE TARGET'S ArtMethod IS NEVER WRITTEN. No SetEntryPoint, no
 * SetNonCompilable, no BackupTo on `target`. Only the throwaway backup ArtMethod is filled in.
 * The patch is keyed on the CODE address (qc), not on the ArtMethod, so the ArtMethod stays
 * byte-identical and `target->GetEntryPoint()` still reads the original qc.
 *
 * KNOWN LIMITS (logged, not hidden):
 *   - one WX patch per PAGE (the KPM's wx table is keyed by page). A second method on an
 *     already-armed page is refused, not merged -> in-place fallback.
 *   - ART is free to recompile the method and move its entry; unlike the clone backend this
 *     path does NOT register with LSPlant's JIT-move registry, so a move silently strands the
 *     patch on the old page (the method then simply runs un-hooked). Hooked at arm time.
 *   - 16-byte patch requires the target address to fit in 48 bits (always true on Android).
 */
int kpm_hide_region(void *addr); /* defined below (mm-gated maps-hide; used by the arm path) */

#define WX_MAX_PAGES 16    /* must not exceed the KPM's WX_MAX (16 slots) */
#define WX_STUB_STRIDE 128 /* bytes per stub slot: 4 relocated insns (<=16 words) + jump (5) */
#define WX_STUB_SLOTS 32   /* stub slots (one VMA-less ghost page each) */

/* Phase B.6 -- the shadow page's MODE, i.e. the optional trailing token of the wxpatch command.
 * These values are the wire protocol with shpte.c's WX_MODE_* (keep the two in step).
 *
 * WX_MODE_FLIP is the original scheme and the DEFAULT (the token is omitted): the PTE flips
 * between the execute-only shadow and the readable ORIGINAL, so readers of the patched 16 bytes
 * -- memcmp / CRC / /proc/pid/mem / any GUP reader -- see the UNTOUCHED bytes. That hiding is
 * the whole point of the backend, so it is given up only when it is the only way to arm at all.
 *
 * WX_MODE_RX is the fallback for a body that reads its own page (wx_body_reads_own_page): a
 * resident readable+executable SHADOW that never flips. Reads and execution both see the shadow,
 * so the read-fault -> exec-fault livelock cannot start. The COST is read-hiding on that page:
 * the patched 16 bytes read back as the patch. Acceptable because the shadow is a byte-identical
 * copy of the original everywhere else, and the pages that need this are JIT pages whose
 * contents are ephemeral (a recompile changes them), so they are not a CRC baseline anyone can
 * rely on. It must NOT be used as a general default -- see red line 1 above. */
#define WX_MODE_FLIP 0 /* --x <-> r-- flip: reads see the ORIGINAL (hidden) */
#define WX_MODE_RX   1 /* resident r-x shadow: reads see the PATCH (read-hiding given up) */

/* Phase B.4 -- THE STUB POOL IS VMA-LESS (see PHASE-B4-VMALESS-STUBS.md).
 * It used to be an mmap(PROT_READ|WRITE|EXEC) page: a real VMA, i.e. an anonymous executable
 * region in /proc/self/maps -- detection surface #2 -- which then had to be hidden by a
 * hide-set entry, and the hide-set (MAX_HIDE=64) was already being spent page-by-page on ART's
 * 1.29MB anon r-xp region (one entry per page, 315 for that region alone), so the pools never
 * got an entry. The fix is to stop creating the VMA at all, the way wxshadow does -- a surface
 * removed rather than hidden, so it costs no hide-set entry and cannot be leaked by a later
 * VMA merge or a missed rescan:
 *
 *   g_wx_stub_src  -- an ordinary PROT_READ|PROT_WRITE page (a pure DATA buffer, so it is not
 *                     an executable region and needs no hiding). Stubs are composed here.
 *   wxstub         -- the KPM copies them into a vmalloc page and injects a PTE for it at a
 *                     ghost VA from the KPM's WXSTUB_VA_BASE window. That page has NO VMA, so
 *                     it is not in maps/smaps/mincore, cannot be munmap'd/mprotect'd, and
 *                     needs no hide-set entry at all -- the budget problem disappears.
 *
 * The stub base handed back to the caller is the GHOST VA, and the stub is entered there.
 * (WX_STUB_GHOST_BASE / the slot count are defined at the top of the file: pick_ghost_va() has
 * to know about the window too.) */
static void *g_wx_stub_src = 0;           /* RW (non-exec) composition page, lazily mmap'd */
static int g_wx_stub_used = 0;            /* ghost stub slots handed out (0..WX_STUB_SLOTS) */
static uint64_t g_wx_stub_ghost[WX_STUB_SLOTS]; /* ghost VA published per slot (diagnostics) */

struct wxent {
    int used;
    uint64_t qc;   /* quick-compiled entry: where the shadow patch is armed */
    uint64_t page; /* qc & ~0xfff -- the page the KPM shadow slot covers */
    uint64_t off;  /* qc - page */
    uint64_t stub; /* relocated call-original stub (VMA-less ghost page we own) */
    int slot;      /* KPM shadow slot index, parsed from the wxpatch reply (for wxrelease) */
    int mode;      /* B.6: WX_MODE_FLIP / WX_MODE_RX this qc was armed with (diagnostics) */
    /* B.7.2: this entry is the SHARED-STUB ROUTER's patch (one per process, on nterp), not a
     * per-method R^X shadow page. The two must never be confused: releasing it through
     * kpm_wx_java_unhooker would disarm the router for EVERY routed method of the process, and a
     * target unhook (whose ArtMethod entry IS that shared stub) would otherwise do exactly that.
     * kpm_wx_java_unhooker refuses such an entry; only the router's own disarm/shutdown path
     * releases it. */
    int router;
};
static struct wxent g_wxents[WX_MAX_PAGES];

/* The COMPLETE set of PC-relative A64 encodings. Everything else is position-independent and
 * can be copied verbatim; an unrecognised PC-relative form would be copied to the wrong address,
 * so this list is checked before the verbatim copy and must stay exhaustive.
 *   B / BL          0x14000000 / 0x94000000   (bits 31:26, the one mask catches both)
 *   B.cond/BC.cond  bits 31:24 = 0x54, bit 4 = 0
 *   CBZ / CBNZ      0x34 / 0x35
 *   TBZ / TBNZ      0x36 / 0x37
 *   LDR (literal)   `opc 011 V 00 imm19 Rt` -- opc 00/01/10/11 = LDR W/X/LDRSW/PRFM and
 *                   V=1 covers LDR S/D/Q (literal); the 0x3B000000 mask ignores V and opc[1],
 *                   so ONE test covers the whole family including PRFM-literal.
 *   LDRAA/LDRAB     base-register relative, NOT PC-relative -> verbatim copy is correct. */
static int wx_is_pc_rel(uint32_t w)
{
    if ((w & 0x7C000000u) == 0x14000000u) return 1; /* B, BL */
    if ((w & 0xFF000010u) == 0x54000000u) return 1; /* B.cond, BC.cond */
    if ((w & 0x7E000000u) == 0x34000000u) return 1; /* CBZ, CBNZ */
    if ((w & 0x7E000000u) == 0x36000000u) return 1; /* TBZ, TBNZ */
    if ((w & 0x3B000000u) == 0x18000000u) return 1; /* LDR/LDRSW/PRFM/LDR S,D,Q (literal) */
    return 0;
}

/* ADR (op=0) / ADRP (op=1): `op 10000 immhi:19 immlo:2 Rd`. Returns 1 and the value the
 * instruction computes, or 0 if `w` is neither.
 * The mask MUST cover both op values: bit 31 is the op, so the test is on bits 28:24 (0b10000)
 * only. Masking bit 31 in (0x9F...) and comparing against ADR's encoding misses ADRP -- which is
 * THE common PC-relative prologue instruction (stack-protector canary / constant pool), and
 * missing it means copying it verbatim, i.e. silently materialising STUB-page-relative garbage.
 * Caught by executing the generated stub on hardware, not by reading the code. */
static int wx_adr_value(uint32_t w, uint64_t pc, uint64_t *out)
{
    if ((w & 0x1F000000u) != 0x10000000u) return 0;
    uint64_t imm = ((uint64_t)((w >> 5) & 0x7FFFFu) << 2) | (uint64_t)((w >> 29) & 3u);
    int64_t simm = (int64_t)(imm << 43) >> 43; /* sign-extend the 21-bit field */
    if (w & 0x80000000u) /* ADRP: page(PC) + (simm << 12) */
        *out = (pc & ~0xFFFULL) + ((uint64_t)simm << 12);
    else
        *out = pc + (uint64_t)simm;
    return 1;
}

/* movz x<rd>, #v[15:0] ; movk x<rd>, #v[31:16],lsl 16 ; ... -- the zero-memory-access way to
 * materialise a 64-bit constant. movz FIRST (it zeroes the rest of the register), movk only for
 * the non-zero upper halves. Neither sets NZCV and neither touches any register but <rd>.
 * Byte-identical in form to the device-proven B.1 patch (`10309bd2 10adb4f2 700fc0f2` =
 * movz x16,#0xd980 / movk x16,#0xa568,lsl16 / movk x16,#0x007b,lsl32 -> 0x7ba568d980). */
static int wx_emit_mov64(uint32_t *o, int cap, uint32_t rd, uint64_t v)
{
    int n = 0;
    if (n >= cap) return -1;
    o[n++] = 0xD2800000u | (uint32_t)((v & 0xFFFFu) << 5) | (rd & 0x1Fu);
    for (int hw = 1; hw < 4; hw++) {
        uint32_t part = (uint32_t)((v >> (hw * 16)) & 0xFFFFu);
        if (!part) continue;
        if (n >= cap) return -1;
        o[n++] = 0xF2800000u | ((uint32_t)hw << 21) | (part << 5) | (rd & 0x1Fu);
    }
    return n;
}

/* Relocate ONE instruction of the patched window into `out`. Returns the words written, or -1
 * with *why set (fail closed -- a wrong address here executes garbage). */
static int wx_reloc_insn(uint32_t w, uint64_t pc, uint64_t page, uint32_t *out, int cap,
                         const char **why)
{
    uint64_t val;
    if (wx_adr_value(w, pc, &val)) {
        /* ADR/ADRP is rebuilt so it produces the ORIGINAL value. If that value lands inside the
         * page we are patching, the instruction that consumes it may do a DATA access to the
         * patched page -- red line 1, a permanent 1:1 livelock -- so refuse instead. */
        if (val >= page && val < page + PAGE_SZ) {
            *why = "ADR/ADRP targets the patched page (red line 1: a consumer would read the "
                   "execute-only shadow view)";
            return -1;
        }
        int k = wx_emit_mov64(out, cap, w & 0x1Fu, val);
        if (k < 0) *why = "stub overflow rebuilding an ADR/ADRP";
        return k;
    }
    if (wx_is_pc_rel(w)) {
        *why = "PC-relative instruction in the patched window (B/BL/B.cond/CBZ/TBZ/"
               "LDR-literal/PRFM-literal)";
        return -1;
    }
    if (cap < 1) { *why = "stub overflow"; return -1; }
    out[0] = w; /* PC-independent (SUB sp / STP / STR / LDR [Xn] / MOV / ...): verbatim */
    return 1;
}

/* Scan the method body for a literal load/address that resolves INTO the patched page. Such an
 * instruction still runs from the patched page (only the first 16 bytes are redirected), so under
 * the flipping R^X scheme it hits red line 1 the moment it executes: data fault -> flip to the
 * read view -> the retry's instruction fetch faults (UXN) -> flip back -> forever. The method's
 * first 4 instructions are already covered by wx_reloc_insn; this covers the rest of the body,
 * which the patch does not move but which still executes from the shadow page.
 *
 * PHASE B.6: this NO LONGER CAUSES A REFUSAL. A self-reading body is exactly the case the
 * resident r-x shadow (WX_MODE_RX) exists for -- no flip, so no livelock -- so the answer now
 * only SELECTS THE MODE at the arm site below (RX here, FLIP otherwise). It is still worth
 * computing: RX gives up read-hiding for the page, so applying it where FLIP would have worked
 * would be a gratuitous loss of hiding (red line 1).
 *
 * Bounded to the method: the AOT OatQuickMethodHeader code_size at qc-4 when it looks sane, else a
 * scan to the first RET/unconditional B. Either way it is clamped to the end of the patched page,
 * since only in-page targets matter. NOTE (B.7.3) that qc-4 is only a HINT here -- it is not always
 * a code_size (device-measured: it can hold a BL instruction or zero), which is precisely why the
 * ARM decision no longer reads it; for this scan the "wrong" case degrades to the
 * scan-to-the-end-of-page path below, which is the safe direction (extra bytes scanned -> possible
 * false positive -> RX instead of FLIP -> read-hiding lost, never a livelock).
 * Conservative by design: a false positive now costs read-hiding on the page (RX) rather than
 * the hook itself; the opposite error -- FLIP on a self-reading body -- is a livelocked device. */
static int wx_body_reads_own_page(uint64_t qc, uint64_t page)
{
    uint64_t end = page + PAGE_SZ;
    uint64_t limit;
    uint32_t code_size = 0;
    /* qc-4 is the OatQuickMethodHeader's code_size. Only read it when it is inside qc's own page:
     * a qc at a mapping's very first word would otherwise read unmapped memory in OUR process. */
    if ((qc & (PAGE_SZ - 1)) >= 4) code_size = *(const volatile uint32_t *)(uintptr_t)(qc - 4) & 0x3FFFFFFFu;
    if (code_size >= 8 && code_size <= 0x80000)
        limit = qc + code_size;
    else {
        code_size = 0; /* mark "no header" for the stop heuristic below */
        limit = end;   /* unknown extent: bounded by the page, stopping early below */
    }
    if (limit > end) limit = end;
    const uint32_t *p = (const uint32_t *)(uintptr_t)qc;
    for (uint64_t a = qc; a + 4 <= limit; a += 4, p++) {
        uint32_t w = *p;
        uint64_t val;
        if (wx_adr_value(w, a, &val)) {
            if (val >= page && val < page + PAGE_SZ) return 1;
            continue;
        }
        if ((w & 0x3B000000u) == 0x18000000u) { /* LDR-family / PRFM (literal) */
            int64_t off = (int64_t)(((w >> 5) & 0x7FFFFu) << 2); /* imm19<<2, sign-extended below */
            off = (off << 43) >> 43;
            uint64_t tgt = a + (uint64_t)off;
            if (tgt >= page && tgt < page + PAGE_SZ) return 1;
            continue;
        }
        if (!code_size) { /* no usable header: stop at the method end */
            if (w == 0xD65F03C0u) break;                 /* RET */
            if ((w & 0xFC000000u) == 0x14000000u) break;  /* unconditional B (tail) */
        }
    }
    return 0;
}

/* ==========================================================================================
 * Phase B.7.3 -- WHERE does `va` live? ONE rule, ONE maps walk, shared by every wx guard below.
 *
 * CONTRACT: this is the C mirror of module.cpp's QcSiteOf (zygisk/src/main/cpp/module.cpp). The
 * decision of whether a qc may be armed is made THERE, and this is the BACKSTOP: a second,
 * independent implementation of the same rule, so the kernel-adjacent arm cannot be reached with
 * a shared-stub address even if that decision is wrong. The two must be changed TOGETHER -- a
 * backstop that has drifted from the rule it backs up is worse than none, because it still looks
 * like one.
 *
 * WHY A LOCATION RULE. The previous test ("is the word at qc-4 a sane
 * OatQuickMethodHeader::code_size?") infers from the SHAPE OF MEMORY, and its premise is not
 * universally true: five device-measured methods that consequently fell through to the detectable
 * in-place hook had their qc in boot-framework.oat with qc-4 holding an INSTRUCTION word
 * (0x97f3562e, a BL) or zero. A shared stub is ONE address shared by all its users; those five
 * were all different and all in boot-framework.oat, i.e. real per-method AOT bodies that the
 * heuristic was rejecting. The FILE is the reliable question: ART's shared stubs
 * (quick_to_interpreter_bridge, the resolution trampolines, nterp) are functions compiled INTO
 * libart.so, while a method's body is in the .oat/.odex/.art file dex2oat wrote.
 *
 *   site                    meaning                                what the wx guards do
 *   ----------------------  -------------------------------------  ---------------------------
 *   WX_SITE_LIBART          ART's SHARED stubs, no exported symbol  NEVER a per-method R^X target
 *                                                                  (red line 1: a patch there
 *                                                                  reroutes EVERY user)
 *   WX_SITE_OAT             a method's own file-backed AOT body    the only R^X target
 *   WX_SITE_JIT             ART's JIT code cache (ART writes it)   never armed (B.7.0)
 *   WX_SITE_OTHER_EXEC      executable, unrecognised file          not positively AOT: refused by
 *                                                                  the per-method arm gate
 *   WX_SITE_UNKNOWN         no VMA / not executable / unreadable   fail closed everywhere
 *
 * The deliberate EXCEPTION is the shared-stub router (wxr_arm_locked): it arms nterp -- a
 * WX_SITE_LIBART page -- ON PURPOSE, once per process, on an entry resolved from ART's own
 * symbols. That is the backend for exactly the methods that have no body of their own, so it is
 * the one legitimate libart arm and it is NOT routed through the per-method gate below.
 *
 * `*why` is set for EVERY answer, including the permissive one. */
enum wx_site {
    WX_SITE_UNKNOWN = 0,    /* no VMA / not executable / maps unreadable / implausible address */
    WX_SITE_JIT = 1,        /* ART's JIT code cache: jit-code-cache / jit-cache */
    WX_SITE_LIBART = 2,     /* executable libart.so: ART's SHARED stubs live here */
    WX_SITE_OAT = 3,        /* executable .oat/.odex/.art (or a /oat/ path): an own AOT body */
    WX_SITE_OTHER_EXEC = 4, /* executable, but the file is none of the above */
};

static enum wx_site wx_site_of(uint64_t va, const char **why)
{
    const char *unused = 0;
    if (!why) why = &unused;
    if (va < 0x2000) {
        *why = "not a plausible code address (null / below the first page)";
        return WX_SITE_UNKNOWN;
    }
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) {
        *why = "/proc/self/maps unreadable: the file behind this address cannot be determined";
        return WX_SITE_UNKNOWN;
    }
    enum wx_site site = WX_SITE_UNKNOWN;
    int found = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path) >= 3 &&
            va >= (uint64_t)lo && va < (uint64_t)hi) {
            /* va lives in this VMA -- and it is the ONLY VMA that could describe it, since maps
             * regions are disjoint and sorted. Non-executable is UNKNOWN, not a class of its own:
             * a qc we are about to execute that maps shows as non-executable means our model of
             * the process is wrong, so nothing may arm on it. */
            found = 1;
            if (perms[2] != 'x') {
                *why = "the covering mapping is not executable";
            } else if (strstr(path, "jit-code-cache") || strstr(path, "jit-cache")) {
                *why = "the page is ART's JIT code cache (jit-code-cache/jit-cache), which ART "
                       "writes continuously: an R^X shadow page is a SNAPSHOT of it";
                site = WX_SITE_JIT;
            } else if (strstr(path, "libart")) {
                *why = "the page is executable libart.so, where ART's SHARED stubs live "
                       "(quick_to_interpreter_bridge / resolution trampolines / nterp): they have no "
                       "per-method identity, so an R^X patch on this page would reroute every "
                       "method that uses the stub";
                site = WX_SITE_LIBART;
            } else if (strstr(path, ".oat") || strstr(path, ".odex") || strstr(path, ".art") ||
                       strstr(path, "/oat/")) {
                *why = "the page is a file-backed .oat/.odex/.art mapping: a method's own AOT body";
                site = WX_SITE_OAT;
            } else {
                *why = "the page is executable but its file is neither libart.so nor a "
                       ".oat/.odex/.art mapping (in-memory dex / anonymous code)";
                site = WX_SITE_OTHER_EXEC;
            }
            break;
        }
    }
    fclose(f);
    if (!found) {
        *why = "no /proc/self/maps region covers this address (a VMA-less ghost stub?)";
        return WX_SITE_UNKNOWN;
    }
    return site;
}

/* Phase B.7.0 -- is `va` in ART's JIT code cache? 1 = yes, the page must NOT be armed.
 *
 * The R^X shadow page installs a SNAPSHOT of the target page (copied at arm time) and redirects
 * the page's EXECUTION view to that frozen copy. That is sound for file-backed AOT code
 * (boot.oat / app .odex): those pages are never written after load. It is NOT sound for the JIT
 * code cache, which ART keeps writing: code compiled after the snapshot does not exist in it (or
 * the slot still holds the previous method's bytes), so executing it faults. Device-measured:
 * "Fatal signal 4 (SIGILL) at pc=0x5a003d60 /memfd:jit-cache" on a page this backend had armed
 * (mode=RX), at an offset OTHER than the patch site -- i.e. unpatched code on an armed page
 * executing stale bytes. Intermittent (1 run in 4), which is the signature of a race against
 * ART's JIT writes; the I-cache flush was checked and is present, so it is not the cause. Both
 * shadow modes snapshot the page, so FLIP is affected exactly like RX.
 *
 * Expressed through wx_site_of so that this guard and the per-method arm gate in
 * kpm_wx_java_hooker classify by the SAME rule: it is the "JIT or unclassifiable" half of it.
 * WX_SITE_LIBART and WX_SITE_OTHER_EXEC still answer 0 (armable) HERE, because this function's
 * callers include the router's own arm (which targets nterp in libart.so by design) and the raw
 * kpm_wx_patch primitive; the per-method path adds its own stricter gate.
 *
 * FAIL-CLOSED: 1 is also returned when the page cannot be positively classified as non-JIT
 * (maps unreadable, qc outside every VMA, non-executable, or an implausible address). An
 * in-place hook is merely detectable; a stale snapshot is a crash -- so "unknown" must never
 * arm. */
static int wx_page_is_jit(uint64_t va)
{
    const char *why = 0;
    enum wx_site site = wx_site_of(va, &why);
    return site == WX_SITE_UNKNOWN || site == WX_SITE_JIT;
}

/* Is `va`'s page free in THIS process? TRUE only when /proc/self/maps has no region covering
 * [va, va+4096). Fail CLOSED (a failed read means "not free"): the ghost VA is about to have a
 * PTE injected into it, so naming a VA that belongs to a real VMA would clobber that mapping.
 * The KPM independently refuses a ghost VA that already has a valid PTE, but a VMA that has not
 * been faulted in yet has NO PTE -- this check is what covers that case. */
static int wx_ghost_va_free(uint64_t va)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[512];
    int ok = 1;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2) continue;
        if (va < (uint64_t)hi && va + PAGE_SZ > (uint64_t)lo) { ok = 0; break; }
    }
    fclose(f);
    return ok;
}

/* Allocate one stub slot and publish `n` words of it as a VMA-LESS executable page. Called
 * under g_lock. Returns the GHOST VA (the address the stub is entered at), 0 on failure.
 *
 * `template_va` is a page of the target's own executable code (the qc page): the KPM copies its
 * PTE attributes, so the stub page is mapped exactly like real code -- user-readable,
 * non-writable, executable -- instead of from a hard-coded guess.
 *
 * The bytes are composed in g_wx_stub_src, an ordinary RW page: a data buffer, never
 * executable, so it is not an "anomalous executable region" that would need hiding. There is
 * deliberately NO __builtin___clear_cache on it -- the I-cache is synced by the KPM on the
 * KERNEL alias of the page it actually publishes (shpte.c sync_icache), which is the page the
 * CPU fetches from. */
static uint64_t wx_stub_publish_locked(const uint32_t *words, int n, uint64_t template_va)
{
    if (n <= 0 || (size_t)n * 4 > PAGE_SZ) return 0;
    if (!g_wx_stub_src) {
        g_wx_stub_src = mmap(0, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_wx_stub_src == MAP_FAILED) {
            g_wx_stub_src = 0;
            __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                                "[wx] stub source mmap(RW, 4K) failed: errno=%d", errno);
            return 0;
        }
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "[wx] stub source buffer = %p (1 page, RW non-exec: no exec region, "
                            "nothing to hide)", g_wx_stub_src);
    }
    if (g_wx_stub_used >= WX_STUB_SLOTS) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG, "[wx] stub pool exhausted (%d slots)",
                            WX_STUB_SLOTS);
        return 0;
    }
    int i = g_wx_stub_used;
    uint64_t ghost = WX_STUB_GHOST_BASE + (uint64_t)i * PAGE_SZ;
    if (!wx_ghost_va_free(ghost)) {
        __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                            "[wx] stub ghost VA 0x%lx is NOT free in this process (a real mapping "
                            "covers it) -- refusing to inject over it",
                            (unsigned long)ghost);
        return 0;
    }
    memcpy(g_wx_stub_src, words, (size_t)n * 4);
    char cmd[192], out[320];
    snprintf(cmd, sizeof cmd, "wxstub %d 0x%lx 0x%lx %d 0x%lx", g_pid, (unsigned long)ghost,
             (unsigned long)(uintptr_t)g_wx_stub_src, n * 4, (unsigned long)template_va);
    bridge_cmd(cmd, out, sizeof out);
    if (!reply_ok(out)) {
        __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                            "[wx] wxstub(ghost=0x%lx, %d insns) rejected: reply=[%s]",
                            (unsigned long)ghost, n, out);
        return 0;
    }
    g_wx_stub_ghost[i] = ghost;
    g_wx_stub_used++;
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wx] stub %d published VMA-less ghost=0x%lx (%d insns, no VMA -> not in "
                        "maps) reply=[%s]", i, (unsigned long)ghost, n, out);
    return ghost;
}

/* Hide the trampoline pool that this arm just handed us -- named exactly, in the log.
 * LSPlant mints a method's trampoline inside DoHook, BEFORE it calls us, so the moment this arm
 * returns, its pool (an anon rwxp mmap) exists and is visible in /proc/self/maps: a hardened
 * target's startup self-check would see an RWX anonymous page. This is the same job
 * kpm_hide_all_anon_exec does for every region, done for the one region this arm knows about --
 * it costs the SAME single hide-set entry (the KPM dedups on (mm, page)), and it makes the log
 * state plainly which region was minted and hidden here.
 *
 * Which page to name: the KPM's hide-set matches a VMA by its vm_start EXACTLY (shpte.c
 * maps_hide_vma), so we register the START of the VMA that CONTAINS the trampoline -- for
 * LSPlant's usual one-page pool that is the page the trampoline itself sits on, and for a pool
 * that has grown it is still the page whose registration hides the whole pool. Registering the
 * trampoline's own page in a grown pool would hide nothing (page 2 != vm_start).
 *
 * Guarded both ways so this can never widen the hiding rule: the containing VMA must be
 * EXECUTABLE and UNNAMED. If it is file-backed or [anon:...]-labelled (i.e. legitimate memory),
 * nothing is hidden and it says so -- hiding a named/file-backed region is exactly the mistake
 * the old blanket scan made.
 *
 * MUST be called with g_lock RELEASED -- kpm_hide_region takes it.
 * Safety: nothing here is VA-scoped. The page address is only handed to the KPM's do_hidergn,
 * which records (mm, page) for an equality test in its show_map hook and never dereferences the
 * page, so this cannot trigger the B.1 "VA unmapped in the issuing context" kernel panic class
 * even though it runs on the target's own hooking thread. */
static void wx_hide_trampoline(void *trampoline)
{
    if (!trampoline) return;
    uint64_t a = (uint64_t)(uintptr_t)trampoline;
    uint64_t vma_start = 0;
    int anon_exec = 0;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wx] trampoline %p NOT hidden: cannot read /proc/self/maps", trampoline);
        return;
    }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path);
        if (n < 3) continue;
        if (a < (uint64_t)lo || a >= (uint64_t)hi) continue;
        vma_start = (uint64_t)lo;
        anon_exec = perms[2] == 'x' && (n < 4 || !path[0]);
        break;
    }
    fclose(f);
    if (!vma_start || !anon_exec) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wx] trampoline %p is not in an unnamed executable VMA (vma=0x%lx) -- "
                            "nothing hidden (not widening the hide rule)", trampoline,
                            (unsigned long)vma_start);
        return;
    }
    if (kpm_hide_region((void *)(uintptr_t)vma_start))
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "[wx] trampoline pool VMA 0x%lx hidden (targeted: names the region)",
                            (unsigned long)vma_start);
    else
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wx] trampoline pool page 0x%lx NOT hidden (bridge off / hide-set "
                            "full / not gated)", (unsigned long)vma_start);
}

/* Build the per-method call-original stub:
 *     <4 relocated instructions of qc..qc+15>
 *     movz x17,#lo ; movk x17,#mid,lsl16 ; movk x17,#hi,lsl32 ; br x17   -> qc+16
 * x17 (IP1) for the jump-back, NOT x16: a relocated instruction may legitimately carry x16
 * across the window (B.1's `sub x16, sp, #0x2000` / `ldr w31, [x16]` pair does exactly that),
 * so x16 must survive all four. Both are caller-saved scratch at a function entry, which is
 * where this stub is entered from.
 * The jump back is a 3-instruction movz/movk + br rather than a 4-byte `b` because `B` only
 * reaches +-128 MB and the stub is nowhere near the method: B.1 measured the app's odex at
 * 0x6e8a..., anon mmaps land near 0x7b..-0x7f.., and the B.4 ghost stub window is at
 * 0x5580000000 -- tens of GB away in every case. `B` there would be an out-of-range encoding,
 * i.e. a silent wrong-branch. This form is range-free and, like the patch, performs no memory
 * access at all (which is also what keeps it clear of the patched page -- red line 1).
 * Returns 0 (with *why set) rather than emitting anything if any instruction is not relocatable. */
static int wx_build_stub(uint64_t qc, uint64_t resume, uint32_t *out, int cap, const char **why)
{
    int n = 0;
    const uint32_t *in = (const uint32_t *)(uintptr_t)qc;
    uint64_t page = qc & ~(PAGE_SZ - 1);
    for (int i = 0; i < 4; i++) {
        int k = wx_reloc_insn(in[i], qc + (uint64_t)i * 4, page, out + n, cap - n, why);
        if (k < 0) return -1;
        n += k;
    }
    int k = wx_emit_mov64(out + n, cap - n, 17, resume);
    if (k < 0) { *why = "stub overflow"; return -1; }
    n += k;
    if (cap - n < 1) { *why = "stub overflow"; return -1; }
    out[n++] = 0xD61F0220u; /* br x17 */
    return n;
}

/* The 16 bytes written into the shadow page: absolute jump to `target`, zero memory access.
 * movz x16,#t[15:0] ; movk x16,#t[31:16],lsl16 ; movk x16,#t[47:32],lsl32 ; br x16
 * x16 (IP0) is scratch at a function entry, so clobbering it here is ABI-correct, and none of
 * the three moves writes NZCV (the original first instruction may be a flag-setting compare).
 * `target` must fit in 48 bits (bits 63:48 zero) or the sequence cannot express it. */
static int wx_patch_bytes(uint64_t target, uint8_t out[16])
{
    if (target >> 48) return -1;
    uint32_t w[4];
    w[0] = 0xD2800000u | (uint32_t)((target & 0xFFFFu) << 5) | 16u;
    w[1] = 0xF2A00000u | (uint32_t)(((target >> 16) & 0xFFFFu) << 5) | 16u; /* movk, hw=1 */
    w[2] = 0xF2C00000u | (uint32_t)(((target >> 32) & 0xFFFFu) << 5) | 16u; /* movk, hw=2 */
    w[3] = 0xD61F0200u;                                                     /* br x16 */
    memcpy(out, w, 16);
    return 0;
}

/* wxpatch <pid> <hexaddr> <hexbytes> [flip|rx] over the sysinfo bridge. Called under g_lock.
 * This process arms its OWN page: everything the KPM does here (resolve_pte on the recorded mm,
 * access_process_vm copy-out, the ADMIN-classified flush) is kernel-alias or non-VA-scoped, so
 * no VA-scoped operation is ever issued from a context where the target VA is unmapped --
 * the mistake that panicked the kernel in B.1. The user VA is mapped in this process by
 * construction (it is this process's own compiled method).
 *
 * `mode` is WX_MODE_FLIP or WX_MODE_RX and is sent as a trailing token; the KPM defaults to
 * FLIP when it is absent, so passing the token explicitly for FLIP is belt-and-braces only. */
static int wx_patch_locked(uint64_t addr, const uint8_t patch[16], int *slot_out, int mode)
{
    static const char hx[] = "0123456789abcdef";
    char hex[33];
    for (int i = 0; i < 16; i++) {
        hex[i * 2] = hx[(patch[i] >> 4) & 0xf];
        hex[i * 2 + 1] = hx[patch[i] & 0xf];
    }
    hex[32] = 0;
    char cmd[192], out[512];
    snprintf(cmd, sizeof cmd, "wxpatch %d 0x%lx %s %s", g_pid, (unsigned long)addr, hex,
             (mode == WX_MODE_RX) ? "rx" : "flip");
    bridge_cmd(cmd, out, sizeof out);
    /* One log line per arm (an arm happens once per hook, never per flip): the KPM's reply echoes
     * the shadow slot, the page, the mode, the PTE it captured and the exact bytes armed, so a
     * mis-encoding is visible in logcat instead of surfacing as a crash in the target method. */
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wx] arm addr=0x%lx mode=%s patch=%s reply=[%s]", (unsigned long)addr,
                        (mode == WX_MODE_RX) ? "RX" : "FLIP", hex, out);
    if (!reply_ok(out)) return -1;
    if (slot_out) {
        const char *s = strstr(out, "slot=");
        *slot_out = s ? atoi(s + 5) : -1;
    }
    return 0;
}

/* Public bridge entry (Phase B.2 A): arm the R^X shadow page at `addr` with a 16-byte patch.
 * Returns 0 on success. Used by kpm_wx_java_hooker below and available to callers that build
 * their own patch. */
int kpm_wx_patch(uint64_t addr, const uint8_t patch[16])
{
    int rc;
    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wx] not armed: bridge off or process not gated");
        rc = -1;
    } else {
        const char *site_why = 0;
        enum wx_site site = wx_site_of(addr & ~(PAGE_SZ - 1), &site_why);
        if (site != WX_SITE_OAT) {
            /* Phase B.7.0 + B.7.3, the same location rule kpm_wx_java_hooker enforces, applied at
             * the other arm entry: this raw primitive is the only remaining way to arm a page, so
             * it needs the same refusal or the hole just moves here. Two independent reasons to
             * refuse, both fail-closed: a page ART keeps writing (the JIT cache) is a crash rather
             * than a trade-off, and a libart.so page (ART's SHARED stubs) is a process-wide
             * reroute -- neither is a per-method body. The router's nterp arm does NOT come
             * through here (it calls wx_patch_locked directly), so this gate does not apply to it. */
            __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                                "[wx] REFUSED addr=0x%lx -> not armed. reason: this raw arm entry "
                                "point patches a file-backed AOT body (.oat/.odex/.art) only; %s",
                                (unsigned long)addr, site_why);
            rc = -1;
        } else {
            /* Callers of this entry point get the DEFAULT mode (read-hiding preserved). The
             * self-reading case cannot be detected from here -- it needs the method body, which
             * only kpm_wx_java_hooker has -- so this path must never silently choose RX. */
            rc = wx_patch_locked(addr, patch, 0, WX_MODE_FLIP);
        }
    }
    pthread_mutex_unlock(&g_lock);
    return rc;
}

static struct wxent *wx_find_qc_locked(uint64_t qc)
{
    for (int i = 0; i < WX_MAX_PAGES; i++)
        if (g_wxents[i].used && g_wxents[i].qc == qc) return &g_wxents[i];
    return 0;
}
static struct wxent *wx_find_page_locked(uint64_t page)
{
    for (int i = 0; i < WX_MAX_PAGES; i++)
        if (g_wxents[i].used && g_wxents[i].page == page) return &g_wxents[i];
    return 0;
}

/* LSPlant hooker (`qc` = the method's quick-compiled entry, `trampoline` = LSPlant's generated
 * trampoline). Builds the relocated call-original stub, arms the shadow page, and returns the
 * STUB (which the caller installs as the backup ArtMethod's entry). Returns NULL after logging
 * the exact reason -> the caller falls back to the in-place entry swap. */
void *kpm_wx_java_hooker(void *qc_, void *trampoline)
{
    void *ret = 0;
    uint64_t qc = (uint64_t)(uintptr_t)qc_;
    const char *why = 0;
    uint32_t words[WX_STUB_STRIDE / 4];
    int n = 0;

    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wx] %p refused: bridge off or process not gated", qc_);
        goto out;
    }
    if (!qc || !trampoline) { why = "null qc/trampoline"; goto refuse; }
    uint64_t page = qc & ~(PAGE_SZ - 1);
    uint64_t off = qc - page;
    if (off + 16 > PAGE_SZ) { why = "the 16-byte patch would cross the page"; goto refuse; }

    /* Phase B.7.0 + B.7.3 -- ONE classification, before any resource is committed (no stub slot
     * burnt, no ghost VA published) and before the mode choice below, because neither FLIP nor RX
     * can make a snapshot of a live page safe.
     *
     * B.7.0: NEVER arm a JIT code-cache page. The shadow page is a SNAPSHOT taken here, while ART
     * keeps writing the real page -- so code compiled after this moment (or the previous occupant
     * of a recycled slot) executes stale bytes and SIGILLs. Measured on device; see wx_page_is_jit.
     * Refusing costs only read-hiding: the caller falls back to the in-place entry swap, which is
     * DETECTABLE but does not crash. This is also what covers the deferred `fc` upgrade path:
     * force-compiling a method puts its body in the JIT cache by construction, so the re-arm
     * attempt is refused here and stays in-place.
     *
     * B.7.3: red line 1 -- a per-method R^X patch belongs on the method's OWN AOT body, so the page
     * must be POSITIVELY a file-backed .oat/.odex/.art mapping. A page in libart.so holds ART's
     * SHARED stubs (quick_to_interpreter_bridge, the resolution trampolines, nterp): they have no
     * exported symbol, so location is the only way to tell them apart from a body, and a patch on
     * one reroutes EVERY method in the process that uses it -- process-wide and irreversible.
     * Anything else unclassifiable (anonymous/in-memory-dex code, an unknown file, a non-executable
     * mapping) is refused too: fail closed (red line 3). This is the backstop for module.cpp's
     * QcSiteOf, which makes the same decision one layer up -- change them together (see the contract
     * on wx_site_of). The router's own arm (wxr_arm_locked) is deliberately NOT behind this gate:
     * arming nterp in libart.so once, with an entry resolved from ART's symbols, is exactly its job,
     * and it keeps using wx_page_is_jit directly. */
    {
        const char *site_why = 0;
        enum wx_site site = wx_site_of(page, &site_why);
        if (site == WX_SITE_JIT) {
            why = "the qc page is ART's JIT code cache (jit-code-cache/jit-cache), which ART writes "
                  "continuously: an R^X shadow page is a snapshot, so code compiled after it would "
                  "execute stale bytes (SIGILL, device-measured). Not archivable by this backend "
                  "(FLIP and RX both snapshot); use the in-place hook instead.";
            goto refuse;
        }
        if (site != WX_SITE_OAT) {
            why = site_why;
            goto refuse;
        }
    }

    {
        struct wxent *dup = wx_find_qc_locked(qc);
        if (dup) {
            /* already armed for this exact entry. The shadow page's bytes are immutable once
             * armed (the KPM has no "re-patch" command), so a re-hook with a NEW trampoline cannot
             * be honoured -- returning the old stub would silently route to the OLD hook. Refuse.
             * The ROUTER's own entry (B.7.2) lands here too, and for a stronger reason: it is
             * ART's SHARED interpreter stub, so a per-method shadow page over it would reroute
             * every interpreted method of the process. */
            why = dup->router
                      ? "this qc is the SHARED-STUB ROUTER's entry (ART's shared interpreter "
                        "stub): the page's one patch belongs to the router, and a per-method "
                        "shadow page here would reroute every interpreted method"
                      : "this qc already carries a WX patch (shadow bytes are immutable; unhook "
                        "first)";
            goto refuse;
        }
    }
    struct wxent *e = wx_find_page_locked(page);
    if (e) {
        why = "the page already carries a WX patch for another method (one patch per page)";
        goto refuse;
    }
    /* Phase B.6: a self-reading body is no longer a refusal -- it selects the MODE. Under FLIP
     * such a body livelocks (read fault -> flip to r-- -> the retry's fetch is refused by UXN ->
     * flip back -> forever, B.1 device-measured), but the resident r-x shadow (RX) has no flip
     * to livelock on: both the read and the fetch see the same shadow page. The trade is that
     * this page reads back PATCHED (read-hiding given up), which is why the test is still run
     * and RX is chosen only where FLIP genuinely cannot work (red line 1). Measured motivation:
     * JIT bodies almost always load constants from their own page, so the old refusal rejected
     * 5 of 6 candidates and pushed them onto the detectable in-place entry swap. */
    int self_reads = wx_body_reads_own_page(qc, page);
    int mode = self_reads ? WX_MODE_RX : WX_MODE_FLIP;
    n = wx_build_stub(qc, qc + 16, words, (int)(sizeof words / sizeof words[0]), &why);
    if (n < 0) goto refuse;

    int idx = -1;
    for (int i = 0; i < WX_MAX_PAGES; i++)
        if (!g_wxents[i].used) { idx = i; break; }
    if (idx < 0) { why = "wx table full"; goto refuse; }

    /* the stub's attribute template is the qc page itself: real, present, user-executable code
     * of this process (the same page we just read the method body from, and whose PTE wxpatch is
     * about to shadow). The stub page is therefore mapped exactly like .text. */
    uint64_t stub = wx_stub_publish_locked(words, n, page);
    if (!stub) { why = "stub publish failed (ghost VA taken / wxstub rejected / pool exhausted)"; goto refuse; }

    /* NOTE: the stub slot is NOT handed back on the two failures below, unlike the old mmap'd
     * pool. A published ghost VA is burnt in the KPM (it refuses a second wxstub at a VA it has
     * already published, which is exactly the red line that stops a real page being clobbered),
     * and the slot index IS the ghost VA -- returning the slot would make the NEXT arm re-use
     * that VA and be rejected forever, turning one refusal into a permanent one. Burning one of
     * WX_STUB_SLOTS per failed arm is the correct trade. */
    uint8_t patch[16];
    if (wx_patch_bytes((uint64_t)(uintptr_t)trampoline, patch) != 0) {
        why = "trampoline address needs more than 48 bits";
        goto refuse;
    }
    int slot = -1;
    if (wx_patch_locked(qc, patch, &slot, mode) != 0) {
        why = "wxpatch rejected (see the reply in the [wx] arm line above)";
        goto refuse;
    }
    g_wxents[idx].used = 1;
    g_wxents[idx].qc = qc;
    g_wxents[idx].page = page;
    g_wxents[idx].off = off;
    g_wxents[idx].stub = stub;
    g_wxents[idx].slot = slot;
    g_wxents[idx].mode = mode;
    ret = (void *)(uintptr_t)stub;
    /* The ARMED line must name the MODE: FLIP and RX differ in a way the operator cannot
     * otherwise see from the outside (one hides reads, one provably cannot), and RX is also the
     * only state where /proc/pid/mem reading the PATCH is expected rather than a bug. */
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wx] ARMED qc=0x%lx (page=0x%lx off=0x%lx) shadow slot=%d mode=%s%s -> "
                        "trampoline %p; call-original stub=%p (%d insns, VMA-less); target "
                        "ArtMethod untouched",
                        (unsigned long)qc, (unsigned long)page, (unsigned long)off, slot,
                        (mode == WX_MODE_RX) ? "RX" : "FLIP",
                        self_reads ? " (body reads its own page: read-hiding given up on this "
                                     "page, reads of the patched 16 bytes will show the patch)"
                                   : "",
                        trampoline, (void *)(uintptr_t)stub, n);
    pthread_mutex_unlock(&g_lock);
    /* B.3/B.4: LSPlant minted this method's trampoline inside DoHook, BEFORE it called us -- so
     * the moment we return, its pool exists and is visible in /proc/self/maps. Close that window
     * to milliseconds by hiding, with g_lock RELEASED (kpm_hide_region takes it):
     *   1) the pool's own VMA start (wx_hide_trampoline: names the exact region in the log), then
     *   2) every unnamed executable region (kpm_hide_all_anon_exec) -- which now costs ONE
     *      hide-set entry per region instead of one per page, so it is affordable on this path
     *      (the per-page walk used to spend all 64 entries on ART's single 1.29MB in-memory-dex
     *      region and leave the pools themselves visible).
     * Our own stub needs no hiding at all: it has no VMA (see wx_stub_publish_locked).
     * Only on the success path: a refusal falls back to the in-place hook, whose trampolines are
     * covered by the scan the module runs right after InitHooks. */
    if (ret) {
        wx_hide_trampoline(trampoline);
        int hid = kpm_hide_all_anon_exec();
        if (hid)
            __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                                "[wx] post-arm anon-exec hide: %d region(s) (g_lock released)", hid);
    }
    return ret;

refuse:
    __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                        "[wx] REFUSED qc=%p -> in-place hook fallback. reason: %s",
                        qc_, why ? why : "unknown");
out:
    pthread_mutex_unlock(&g_lock);
    /* Nothing to hide on this path any more: a refusal can leave a published stub ghost, but it
     * is VMA-less, so it is invisible to maps/smaps without any hide-set entry. */
    return ret;
}

/* Disarm one WX hook by its quick-compiled entry (the ArtMethod entry is NEVER written by this
 * backend, so the caller can always recover it with target->GetEntryPoint()). Returns 1 if a
 * patch was released, 0 if this qc was never WX-hooked. */
int kpm_wx_java_unhooker(void *qc_)
{
    int ok = 0;
    uint64_t qc = (uint64_t)(uintptr_t)qc_;
    pthread_mutex_lock(&g_lock);
    if (!g_inited) goto out;
    struct wxent *e = wx_find_qc_locked(qc);
    if (!e) goto out; /* not a WX-hooked method -> not an error */
    /* B.7.2 red line: the shared-stub router's patch is keyed on the SHARED entry (nterp), and a
     * router-routed method's ArtMethod entry IS that shared stub -- so a caller that unhooks such a
     * method would otherwise find the router's own g_wxents entry here and release it, disarming
     * the router for EVERY routed method at once. The router is released only by its own disarm /
     * kpm_hook_shutdown. */
    if (e->router) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wx] unhook REFUSED qc=0x%lx: this is the SHARED-STUB ROUTER's patch "
                            "(armed on ART's shared interpreter entry), not a per-method R^X "
                            "shadow page -- releasing it would stop routing every method of this "
                            "process at once. Unhook the router itself instead.",
                            (unsigned long)qc);
        goto out;
    }
    if (e->slot >= 0) {
        char cmd[64], out[192];
        snprintf(cmd, sizeof cmd, "wxrelease %d", e->slot);
        bridge_cmd(cmd, out, sizeof out);
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "[wx] release qc=0x%lx slot=%d reply=[%s]", (unsigned long)qc, e->slot,
                            out);
        if (!reply_ok(out)) goto out; /* leave the entry in place: the patch is still live */
    }
    memset(e, 0, sizeof(*e));
    ok = 1;
out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

/* ==========================================================================================
 * SHARED-STUB ROUTER (B.7.1 mechanism proof, B.7.2 wired into the hook path; see
 * PHASE-B7-1-ROUTER-POC.md, PHASE-B7-2-DOHOOK-WIRING.md and the contract in kpmhook.h).
 *
 * WHY IT EXISTS. B.7.0 closed the coverage gap's wrong half: a JIT page must never be armed.
 * The remaining gap is the other half -- a method with NO independent compiled body points its
 * `entry_point_` at one of ART's SHARED interpreter stubs (`nterp_entry_point`,
 * quick_to_interpreter_bridge, quick_resolution_trampoline). A shared stub cannot be patched per
 * method (every method using it shares it) and rewriting the method's ArtMethod entry is the
 * in-place fallback we are trying to get away from. rustFrida's answer, and this one's, is to
 * patch the SHARED entry ONCE with a jump to a router that dispatches on `x0` -- the ArtMethod*
 * per ART's quick ABI (P1) -- and then continues into the stub. The replacement is the `hook`
 * ArtMethod LSPlant already hands to DoHook, so the router only ever rewrites x0 (P2).
 *
 * B.7.1 proved exactly that (device: hits=20, and C("probe") returned A:probe) but nothing called
 * it. B.7.2 wires it in: kpm_wx_router_add() is what LSPlant's shared_router_hooker calls for a
 * method whose qc IS nterp_entry_point, i.e. for precisely the methods that used to end in the
 * detectable in-place entry swap. The table below therefore holds N methods, not one, and every
 * entry is an ArtMethod* pair -- `target` is only ever COMPARED, never written.
 *
 * WHY IT IS SAFE ON THIS PAGE. `nterp_entry_point` is in libart.so: a file-backed, read-only,
 * never-rewritten mapping -- exactly the page class R^X is sound on (P3), and the opposite of
 * the JIT cache B.7.0 banned (P4). The 16-byte patch and the relocation of the covered window
 * both come from the B.1/B.2 machinery below, unchanged.
 *
 * THE FOUR RED LINES THIS CODE IS BUILT AROUND
 *   1. NO JIT PAGE. wx_page_is_jit() is checked first, before any resource is committed.
 *   2. NO HARDCODED OFFSET. The entry is a parameter; the caller resolves it from ART's symbols.
 *      A null entry is refused here too, so a caller that forgets cannot arm at address 0.
 *   3. THE ROUTER MUST NOT READ THE PATCHED PAGE. The router reads only its own ghost page
 *      (instructions), the stack, and the table in this library's .bss. The replayed window is
 *      relocated into the ghost page, so the covered instructions execute from OUR page; a
 *      PC-relative or same-page-literal covered instruction is refused outright before arming
 *      (see the "covered insn" log lines), and the rest of the stub's body -- which still runs
 *      from the shadow page -- selects RX via wx_body_reads_own_page, exactly as B.6 does.
 *   4. THE MISS PATH MUST BE INDISTINGUISHABLE FROM THE UNPATCHED PATH. This is a GLOBAL entry:
 *      every interpreted call in the process goes through it. The router is therefore written as
 *      a save/restore frame around a C dispatch (see wxr_build_router). It restores EVERY
 *      general-purpose register it touched, NZCV, and SP before the first replayed instruction
 *      runs -- x0 alone carries the dispatch result. The ONE deliberate exception is x16/IP0 at
 *      the final branch (the branch target has to be materialised in a register, and no A64
 *      instruction both writes a register and branches to it); x16 is intra-procedure-call
 *      scratch that the caller cannot have live across an indirect call, and the existing,
 *      device-proven backend already clobbers x16 at this very entry (wx_patch_bytes) and x17 in
 *      its stub jump-back (wx_build_stub). x18 is left alone: it is the platform register (the
 *      shadow-call-stack pointer on Android), which the C dispatch preserves by ABI.
 *
 *      The miss path is also why the counters matter: `misses` growing while the process keeps
 *      running IS the red-line-4 evidence, and `kpm_wx_router_poc_arm(entry, 0, 0, off)` -- an
 *      EMPTY table, so every call misses -- is the cleanest way to produce it.
 *
 * WHY THE HIT PATH DOES NOT RESUME THE STUB (the defect this router was fixed for). Swapping x0
 * and continuing into the shared stub is only sound if the stub can run WHATEVER ArtMethod it is
 * handed, and `nterp_entry_point` cannot. nterp's entry is entered by the CALLER under a contract
 * the caller fixed at its own compile time, and everything it needs about the method it must run
 * -- including the access-flag bits that select between its fast and slow entry paths, and the
 * dex/code-item data it will start decoding -- is read from the ArtMethod in x0. Rewriting x0
 * hands it a method that never agreed to that contract: a replacement that ART would have entered
 * some other way (a JNI trampoline, the interpreter bridge, JIT code, or a method whose flags or
 * code item differ) is then fed to nterp as if ART had chosen nterp for it. Device-measured
 * consequences of getting this wrong: `nterp_op_unused_e4` (SIGTRAP) when the swapped-in method
 * was a native ArtMethod, and, on a large real app, a routed framework method silently returning
 * garbage -- both while the miss path stayed clean.
 *
 * So the hit path does what ART's own trampolines do, and what the reference implementation does
 * (`hook_install_art_router`, whose found path ends in
 * `ldr x16, [x0, quickcode_offset] ; br x16` -- the caller's comment: the replacement is
 * `kAccNative`, "ART handles that"): it restores the caller's quick-ABI register state and
 * TAIL-CALLS the replacement through `replacement->entry_point_from_quick_compiled_code_`, the
 * entry point ART itself installed for that method. The stub is never resumed with a rewritten
 * x0, so the "which entry path is this method entered by" decision stays with the method it
 * belongs to instead of being taken over by a stub that was entered for a different one. The
 * covered window is not replayed on a hit either -- that window belongs to the stub's prologue,
 * which a hit does not use.
 *
 * The same invariant decides the two things this router deliberately does NOT copy from the
 * reference's found path:
 *   - It does NOT write `replacement->declaring_class_ = original->declaring_class_`. That sync
 *     exists for the reference's *clone* replacement (a byte-copy of the target method, which must
 *     keep the target's declaring class). Read the reference's guard as written
 *     (hook_engine_art.c, `emit_art_router_found_path`): the sync sits on the mode-0 path only --
 *     `ldr x0,[x16,#16] ; cmp x0,#4 ; b.eq <skip>` is preceded by the mode-4/5 dispatch
 *     (`b.eq`/`b.eq` to the managed tail, which branches out at `br x16` *before* the sync), so at
 *     the sync site the mode can only be 0 and the `cmp #4` guard never fires -- i.e. the case the
 *     reference actually syncs is the CLONE case, and the case it never reaches is its helper-dex
 *     (managed, mode 4/5) replacement. This router's replacement is exactly that kind: a hook
 *     method living in its own generated dex class (LSPlant's BuildDex class), handed to DoHook as
 *     `hook`. Copying the target's declaring class onto it would point its dex-cache/code-item
 *     resolution at the wrong dex, corrupt the helper's class metadata, and (for the static-field
 *     hooker lookup and the jclass ART passes a static hook) change the receiver class the hook
 *     method is invoked with. Do NOT "restore" this sync.
 *   - It does NOT keep a router frame on the stack during the replacement's execution: the frame
 *     is released (see the hit path in wxr_build_router) before the branch, so the replacement's
 *     own entry establishes its own frame exactly as it would for any other caller, and this
 *     router's ghost page and frame stay off ART's stack walk. This is NOT the same trade as the
 *     reference's SP+0 publication -- that one exists because its thunk IS the frame ART attributes
 *     the call to (its entry point is the thunk, so its frame needs a valid method slot, published
 *     as `replacement` so `ToDexPc` takes the native early exit, plus a fake OatQuickMethodHeader
 *     for its PC). Here the frame ART attributes the call to is the REPLACEMENT's own frame,
 *     entered through ART's own entry for that method; a frame of ours between them is a frame ART
 *     cannot walk: it reads the ArtMethod from `*frame_base` and advances the walk by that
 *     method's code size, so `replacement_frame_base + code_size(replacement)` lands exactly on the
 *     router frame's base -- slot 0, deliberately never written -- and the walker continues with
 *     garbage. Removing the frame (popping it, exactly as the miss path already does) is the only
 *     sound answer for a router that is not itself a method: a single valid method slot would still
 *     be paired with a frame size ART derives from that method's own code, which is not this
 *     frame's size.
 *
 * REENTRANCY / NO BLOCKING (red line 5). The router takes no lock, issues no syscall, allocates
 * nothing, and calls nothing that can re-enter ART. Its C dispatch is one acquire load, a bounded
 * scan of at most WXR_ALL_ENTRIES entries (a LENGTH check first, so an empty table costs one
 * compare and the common one-method table costs one more), and two counter increments. The scan is
 * bounded by the table's own cap, never by anything a caller controls, and it is not a retry loop:
 * it either finds the entry or does not. The increments are plain read-modify-writes, not LL/SC
 * retry loops: a lost increment under concurrency is acceptable for a diagnostic, and a spin in a
 * global entry point is not.
 *
 * B.7.2 ADDED TWO RED LINES OF ITS OWN.
 *   6. THE TABLE IS CAPPED AND FAILS CLOSED. 64 routed methods per process; the 65th add is
 *      REFUSED (kpm_wx_router_add) and that method keeps the in-place hook, with the reason in
 *      logcat. The cap is checked BEFORE the arming, so a fresh arm can never leave the process
 *      with a globally armed entry for a method that is then refused. The router itself has no
 *      "table full" path to take: it reads `count`, which the writer can only ever publish at a
 *      value the cap allows.
 *   7. ONE ARM PER PROCESS, ONE PATCH PER PAGE. kpm_wx_router_add refuses an entry other than the
 *      armed one (there is one nterp), and the caller refuses the with-clinit nterp entry outright
 *      because it shares nterp's page (0x40 away, device-measured) and the page's single patch is
 *      spent. That refusal is the caller's (it is the only side that can compare symbol values);
 *      see wx_router_poc.cpp.
 * ========================================================================================== */

/* The router is ~40 words today (save/dispatch/restore + a 4-insn window that can expand to 4x
 * when it holds an ADR/ADRP). Sized with room to spare; a router that outgrows this refuses to
 * arm instead of truncating. */
#define WXR_MAX_WORDS 256

/* Router stack frame: 20 slots, 160 bytes (16-byte aligned, so the `blr` into the C dispatch
 * satisfies AAPCS64). Slot k lives at sp + k*8; slot 0 is deliberately unused (it would hold x0,
 * which is the dispatch's result and must NOT be restored).
 *   1,2  x1,x2    3,4  x3,x4    5,6  x5,x6     7,8   x7,x8     9,10  x9,x10
 *   11,12 x11,x12 13,14 x13,x14 15,16 x15,x16  17,18 x17,x30   19    nzcv
 * Everything saved is CALLER-saved state the C dispatch is free to clobber (x0-x17, x30, NZCV).
 * x18-x28 and x29 need no saving: the callee preserves them.
 *
 * LIFETIME (both exits depend on it, and wxr_build_router refuses to emit a router that breaks
 * it): the frame exists ONLY across the C dispatch. It is released before EITHER exit branches --
 * the miss exit because the miss path must be indistinguishable from the unpatched entry, the hit
 * exit because a frame ART can see but cannot walk corrupts the stack walk (see the hit path in
 * wxr_build_router; slot 0 is never written, and it is the slot ART would read as the frame's
 * ArtMethod). Nothing may read the frame after the dispatch except the restore sequence itself. */
#define WXR_FRAME 160
#define WXR_SLOT(k) ((k) * 8)

/* --- the emitters. Kept as explicit encoders rather than magic constants so a wrong bit shows
 * up as a wrong bit here, where it can be read, and not as a crash inside the interpreter. --- */

/* stp x<rt>, x<rt2>, [sp, #off]  (64-bit, signed offset; off >= 0, multiple of 8, <= 504) */
static uint32_t wxr_stp_sp(int rt, int rt2, int off)
{
    return 0xA9000000u | ((uint32_t)(off / 8) << 15) | ((uint32_t)rt2 << 10) | (31u << 5) |
           (uint32_t)rt;
}
/* ldp x<rt>, x<rt2>, [sp, #off] */
static uint32_t wxr_ldp_sp(int rt, int rt2, int off)
{
    return 0xA9400000u | ((uint32_t)(off / 8) << 15) | ((uint32_t)rt2 << 10) | (31u << 5) |
           (uint32_t)rt;
}
/* str x<rt>, [sp, #off] / ldr x<rt>, [sp, #off] (unsigned offset, off multiple of 8) */
static uint32_t wxr_str_sp(int rt, int off)
{
    return 0xF9000000u | ((uint32_t)(off / 8) << 10) | (31u << 5) | (uint32_t)rt;
}
static uint32_t wxr_ldr_sp(int rt, int off)
{
    return 0xF9400000u | ((uint32_t)(off / 8) << 10) | (31u << 5) | (uint32_t)rt;
}
/* sub sp, sp, #imm / add sp, sp, #imm -- ADD/SUB (immediate) on SP. Neither sets NZCV (S=0),
 * which the restore order below depends on. */
static uint32_t wxr_sub_sp(int imm)
{
    return 0xD1000000u | ((uint32_t)imm << 10) | (31u << 5) | 31u;
}
static uint32_t wxr_add_sp(int imm)
{
    return 0x91000000u | ((uint32_t)imm << 10) | (31u << 5) | 31u;
}
#define WXR_MRS_NZCV_X16 0xD53B4210u /* mrs x16, nzcv  -- reads NZCV, writes x16 only */
#define WXR_MSR_NZCV_X16 0xD51B4210u /* msr nzcv, x16  -- writes NZCV, reads x16 only */
#define WXR_BLR_X16 0xD63F0200u      /* blr x16 */
#define WXR_BR_X16 0xD61F0200u       /* br  x16 (identical to wx_patch_bytes' branch) */
#define WXR_MOV_X16_X1 0xAA0103F0u   /* mov x16, x1 -- the dispatch's hit flag, see wxr_dispatch */

/* The three instructions of the HIT path (see wxr_build_router). `movz` is a single 16-bit
 * immediate: the field offset it must hold is a small constant of ART's ArtMethod layout (the
 * compiler's entry-point slot), so no movz/movk pair and no literal pool is needed. */
static uint32_t wxr_movz_x16(uint32_t imm16)
{
    return 0xD2800010u | ((imm16 & 0xFFFFu) << 5); /* movz x16, #imm16 */
}
#define WXR_LDR_X16_X0_X16 0xF8706810u /* ldr x16, [x0, x16] -- 64-bit LDR (register offset) */
/* cbz x16, <imm19 words>. The offset field is ZERO here and patched in place once the miss
 * label's word index is known (wxr_build_router emits everything in one pass, so the only branch
 * it needs is a forward one). */
static uint32_t wxr_cbz_x16(unsigned words_ahead)
{
    /* The 32-bit form (`cbz w16`, sf=0) is deliberate: the value tested is the dispatch's hit flag,
     * which is only ever 0 or 1, so the upper half of x16 cannot matter here. */
    return 0x34000010u | ((words_ahead & 0x7FFFFu) << 5); /* cbz w16, label */
}

/* ---- THE TABLE, and how it is updated while the router is live -----------------------------
 *
 * B.7.1 could route exactly ONE method: the table was a single {target, replacement} pair. B.7.2
 * wires the router into DoHook, so the table has to hold one entry per routed method of the
 * process while the router keeps running on EVERY interpreted call. The shape below is the B.7.1
 * publication scheme generalised to N entries -- same guarantee, same read cost.
 *
 * WHERE THE ENTRIES COME FROM (and why a property is not enough). An ArtMethod* is a per-process
 * address (class-linker linear alloc under ASLR), so the router's real table is installed by the
 * process itself: kpm_wx_router_add() from the hook path, one entry per routed method, keyed on
 * the ArtMethod* the CALLER passes in x0. The B.7.1 property harness (`persist.kpmhook.routerpoc.am`
 * / `.repl`) still exists for testing the mechanism, but its pair is kept SEPARATELY from the
 * programmatic entries, so a test publication can never clobber a live hook. Every publication
 * rebuilds the table from both: the programmatic entries first, then the property pair.
 *
 * TORN READS ARE THE WHOLE PROBLEM, and a pair of stores cannot avoid them. The router reads a
 * pair (target, replacement) that must agree: (new_target, old_replacement) would hand the
 * interpreter an ArtMethod* the caller never called -- arbitrary wrong method, not a near miss.
 * Clearing target first does not fix it either: a reader that still sees the old target can
 * already observe the new replacement.
 *
 * So a whole TABLE is published by POINTER, not by rewriting one in place:
 *   - two tables, each immutable once published, {count, entries[]}, and one `g_wxr_active`
 *     pointer;
 *   - the writer only ever fills the table that is NOT active, then flips the pointer with a
 *     RELEASE store;
 *   - the router does ONE acquire load of the pointer and then reads the count and both fields of
 *     every entry out of the table that pointer names.
 * A reader therefore sees either the old table or the new one, and never a mixture of the two --
 * the torn state does not exist, it is not merely improbable. That is why this shape was chosen
 * over a generation counter: a seqcount would need the ROUTER to retry, and a retry loop in a
 * global interpreter entry point is exactly the spin red line 5 forbids. Here the router's cost
 * is unchanged (one dependent load pair) plus a bounded scan, and it still never locks, never
 * blocks and never allocates. The release/acquire pair is the ARMv8.0 baseline ldar/stlr clang
 * emits for these builtins, so nothing here needs a newer CPU than the rest of the backend.
 *
 * The write side's one precondition: a single writer at a time (g_lock), which only ever touches
 * the INACTIVE table. A reader that loaded the pointer must finish its (bounded, tens of
 * instructions) scan before that same slot is refilled -- i.e. before TWO publications intervene.
 * The routing install path publishes from DoHook, which runs under ScopedSuspendAll (no other
 * thread runs at all), and the 1 Hz harness poll publishes only when its property pair changed, so
 * the window is not reachable in practice.
 *
 * The counters live OUTSIDE the tables: they must keep accumulating across publications. */
/* Sizes come from kpmhook.h so the published stats struct cannot drift out of step with the
 * table it reports on (KPM_WXR_MAX_ENTRIES = the fail-closed cap on routed methods). */
#define WXR_MAX_ENTRIES KPM_WXR_MAX_ENTRIES
#define WXR_ALL_ENTRIES KPM_WXR_SLOT_COUNT

struct wxr_entry {
    uint64_t target;      /* ArtMethod* to match; 0 = unused slot (never a hit) */
    uint64_t replacement; /* ArtMethod* the router enters instead of `target` */
};
struct wxr_table {
    uint32_t count; /* entries in use; the reader never looks past this */
    struct wxr_entry e[WXR_ALL_ENTRIES];
};
static struct wxr_table g_wxr_tables[2]; /* never mutate the ACTIVE one; only publish it */
static void *volatile g_wxr_active;      /* acquire/release: which table the router reads */
static uint64_t g_wxr_hits;
static uint64_t g_wxr_misses;
static uint64_t g_wxr_publishes;         /* table updates after the initial arm (diagnostics) */
/* Per-SLOT-POSITION hit counters, indexed by the position in the live table. The router writes
 * them with a plain store (no lock, no allocation -- red line 5); a count therefore belongs to a
 * table position rather than forever to a method, which is why every dump prints {position,
 * target, replacement, count} together. Diagnostics, not accounting. */
static uint64_t g_wxr_slot_hits[WXR_ALL_ENTRIES];

/* The AUTHORITATIVE model, mutated only under g_lock. The published tables are derived from it. */
static struct wxr_entry g_wxr_prog[WXR_MAX_ENTRIES]; /* one entry per router-routed method */
static int g_wxr_prog_n;
static int g_wxr_prog_added;   /* stats: adds ACCEPTED (the coverage question of B.7.2) */
static int g_wxr_prog_removed; /* stats: removals */
static int g_wxr_prog_full;    /* stats: adds REFUSED because the cap was reached */
static int g_wxr_prog_upd;     /* stats: adds that updated an existing entry */
static int g_wxr_prop_on;      /* the B.7.1 harness pair is installed as one extra entry */
static uint64_t g_wxr_prop_am;
static uint64_t g_wxr_prop_repl;
static volatile uint64_t g_wxr_armed;    /* 1 = the shared entry carries the router patch */
static uint64_t g_wxr_entry;             /* the armed entry (diagnostics / disarm lookup) */
/* WHERE the HIT path reads the replacement's entry point from: the byte offset of
 * `entry_point_from_quick_compiled_code_` inside an ArtMethod, as resolved by ART's own layout
 * (LSPlant's ArtMethod::Init computes it; Vector passes it down -- never a hardcoded offset, red
 * line 2). Baked into the router as a movz immediate at arm time, so a hit costs one extra load
 * (`ldr x16, [x0, #off]`) and the router never has to know anything else about ArtMethod. */
static uint32_t g_wxr_qc_off;
static uint64_t g_wxr_router;            /* ghost router VA (diagnostics) */
static int g_wxr_mode = WX_MODE_FLIP;    /* WX_MODE_FLIP / WX_MODE_RX, for the log */
static int g_wxr_self_reads;             /* why the mode was chosen */
static int g_wxr_poll_run;               /* poll thread should keep running (under g_lock) */
/* ---- x0 diagnostic (see the block comment above wxr_x0_report) -----------------------------
 * A rolling ring of the most recent misses' x0 values, plus the single most recent one. Written
 * by the router with plain stores only -- no lock, no syscall, no branch it can block on -- and
 * read/logged by the poll thread. */
#define WXR_X0_RING 8
static volatile uint64_t g_wxr_x0_ring[WXR_X0_RING];
static volatile uint64_t g_wxr_x0_idx;   /* total misses tracked (ring index = idx & 7) */
static volatile uint64_t g_wxr_x0_last;
static int g_wxr_x0_track = 1;           /* the router's one-load gate */
static int g_wxr_x0_logged;              /* one-shot: the report has been emitted */
static int g_wxr_x0_ticks;               /* poll ticks since the last (re-)arm of the report */
static uint64_t g_wxr_x0_prop;           /* last value of persist.kpmhook.routerpoc.x0 acted on */
static int g_wxr_poll_started;
static uint64_t g_wxr_seen_target;       /* last prop values ACTED ON, so a rejected pair is not
                                            re-logged once a second (under g_lock) */
static uint64_t g_wxr_seen_repl;

/* The C half of the router: entered from the ghost page with x0 = the called method's ArtMethod*
 * (ART quick ABI, P1) and left with x0 = the ArtMethod* the interpreter must actually run, plus a
 * hit flag in x1 that decides WHICH of the two exits the router takes.
 *
 * The return value is a 16-byte POD, so AAPCS64 returns it in x0/x1 (a composite of at most 16
 * bytes, two INTEGER-class members). x0 is the method to continue with and x1 is 1 only when the
 * table matched. That second register is the whole reason the hit path can be different from the
 * miss path: the miss path must be indistinguishable from the unpatched entry (red line 4), and it
 * still is -- x1 is 0 there and the router's restore sequence reloads x1 from the frame before the
 * replayed window runs, so a missing method's x1 is the CALLER's x1, bit for bit.
 *
 * `noinline` + `used` + taking its address below: the router reaches it by materialising
 * `&wxr_dispatch` at runtime, so the compiler must keep a real out-of-line copy at exactly that
 * address. The body must stay allocation-free, lock-free, syscall-free and non-blocking (red line
 * 5) -- it runs on EVERY interpreted call in this process while armed. The acquire load of
 * g_wxr_active is what makes the published table indivisible; see the table comment above.
 *
 * The scan is BOUNDED BY THE TABLE'S OWN CAP (WXR_ALL_ENTRIES), never by anything a caller
 * controls, and it is not a retry loop -- it either finds the entry or does not. The miss path is
 * the common case in a real process (every interpreted method that is not routed lands here), so
 * the load of `t` and of `count` come first and an empty or short table costs one compare per
 * entry. */
struct wxr_hit {
    void *method; /* x0: the ArtMethod* the shared entry must continue with */
    uint64_t hit; /* x1: 1 = matched (enter `method` through its OWN entry point), 0 = miss */
};
_Static_assert(sizeof(struct wxr_hit) == 16, "wxr_dispatch's return must fit in x0/x1");

__attribute__((noinline, used)) static struct wxr_hit wxr_dispatch(void *art_method)
{
    struct wxr_table *t = (struct wxr_table *)__atomic_load_n(&g_wxr_active, __ATOMIC_ACQUIRE);
    uint64_t m = (uint64_t)(uintptr_t)art_method;
    uint32_t n = t ? t->count : 0;
    for (uint32_t i = 0; i < n; i++) {
        if (t->e[i].target != 0 && t->e[i].target == m) {
            g_wxr_hits = g_wxr_hits + 1;
            g_wxr_slot_hits[i] = g_wxr_slot_hits[i] + 1;
            struct wxr_hit r;
            r.method = (void *)(uintptr_t)t->e[i].replacement;
            r.hit = 1;
            return r;
        }
    }
    g_wxr_misses = g_wxr_misses + 1;
    /* x0 diagnostic. A plain rolling capture, NOT a log call: __android_log_print is a syscall
     * to logd and the router must never block (red line 5), so the router only records and the
     * poll thread does the (blocking) reporting. The cost is one load of g_wxr_x0_track and, when
     * it is on, three stores to a cache line the counters are already dirtying. Turning it off
     * (persist.kpmhook.routerpoc.x0=0) leaves nothing but that one load. */
    if (g_wxr_x0_track) {
        uint64_t i = g_wxr_x0_idx;
        g_wxr_x0_ring[i & (WXR_X0_RING - 1)] = m;
        g_wxr_x0_idx = i + 1;
        g_wxr_x0_last = m;
    }
    struct wxr_hit r;
    r.method = art_method;
    r.hit = 0;
    return r;
}

/* Rebuild the INACTIVE table from the authoritative model (the programmatic entries, then the
 * optional property pair) and publish it with a release store. See the table comment: the ACTIVE
 * table is never touched, so the router keeps reading a consistent table throughout. Called under
 * g_lock by the arm/add/remove paths, the poll thread, and the disarm/shutdown teardown.
 * An empty model publishes an EMPTY table -- the router then misses on every call, which is both
 * the red-line-4 test state and the operator's off-switch. */
static void wxr_republish_locked(void)
{
    struct wxr_table *cur = (struct wxr_table *)g_wxr_active;
    struct wxr_table *nxt = (cur == &g_wxr_tables[0]) ? &g_wxr_tables[1] : &g_wxr_tables[0];
    uint32_t n = 0;
    for (int i = 0; i < g_wxr_prog_n && n < WXR_MAX_ENTRIES; i++) nxt->e[n++] = g_wxr_prog[i];
    if (g_wxr_prop_on && n < WXR_ALL_ENTRIES) {
        nxt->e[n].target = g_wxr_prop_am;
        nxt->e[n].replacement = g_wxr_prop_repl;
        n++;
    }
    nxt->count = n;
    __atomic_store_n(&g_wxr_active, nxt, __ATOMIC_RELEASE);
}

/* Runtime table updates, one property poll per second.
 *
 * A property is the only channel the operator has across processes (the demo is a different APK
 * from the module), and a 1 Hz read of two props costs nothing measurable -- the expensive part
 * of the POC is the per-call dispatch, not this. The thread NEVER runs while holding g_lock
 * (it reads the props, releases, then takes g_lock only to publish), so a slow property read
 * cannot stall a hook install.
 *
 * Precedence, all logged:
 *   `persist.kpmhook.routerpoc.am` / `.repl`   both set   -> publish that pair
 *                                              both clear -> publish an EMPTY table
 *                                              one  set   -> refuse (log once), keep the old pair
 * The values are ArtMethod* from THIS process, e.g. the ones the app logs; a stale value from a
 * previous launch is filtered by wxr_plausible() and, if it survives that, simply never matches. */
static int wxr_prop_is_readable(uint64_t va)
{
    /* ArtMethod objects are DATA: a pointer into executable memory, or into nothing at all, is
     * not one. This is the deref-free half of the check -- it costs a /proc/self/maps scan at
     * 1 Hz and cannot fault, which matters because a bad pointer must not take the app down. */
    if (va < 0x1000 || (va & 7)) return 0;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0; /* fail closed */
    char line[512];
    int ok = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) < 3) continue;
        if (va < (uint64_t)lo || va + 8 > (uint64_t)hi) continue;
        ok = (perms[0] == 'r') && (perms[2] != 'x');
        break;
    }
    fclose(f);
    return ok;
}

static int wxr_plausible(uint64_t target, uint64_t replacement)
{
    if (target == 0) return 1; /* empty table: always acceptable */
    if (target == replacement) return 1;
    return wxr_prop_is_readable(target) && wxr_prop_is_readable(replacement);
}

/* ---- the x0 diagnostic ---------------------------------------------------------------------
 * The question it answers: the router is demonstrably executing (the armed page faults and
 * switches) yet the swap never happens, so `x0` is evidently not the value the table is keyed
 * on. This prints what x0 ACTUALLY is, so the guesswork stops:
 *
 *   - the miss counters. `misses` counts EVERY interpreted call in the process, so misses==0 is
 *     decisive on its own: the router was never entered, and no amount of table fixing helps
 *     (the armed entry is not on this app's call path). That is reported explicitly rather than
 *     left to be inferred from an empty sample list.
 *   - the published `am` vs `nterp_entry_point`, both classified against /proc/self/maps, so the
 *     two address spaces in play (ArtMethod objects, and the code we armed) are distinguishable
 *     at a glance.
 *   - a ring of the most recent x0 values, each classified by mapping and, when it is close to
 *     `am`, by its delta from it (an x0 that is `am+0x20` is a different method in the same
 *     array; a wildly different address is a different convention entirely).
 *
 * A ROLLING ring rather than "the first 8 misses": the first misses after arming are whatever
 * the app happened to run at startup, whereas the ones worth seeing are those nearest the
 * observation (the app's call loop). The report is one-shot so it cannot flood logcat, is
 * re-armed automatically by every table publication (that is the moment worth sampling), and can
 * be re-armed by hand through `persist.kpmhook.routerpoc.x0`.
 *
 * `wxr_describe` runs on the POLL thread (it opens /proc/self/maps), never in the router. */

/* "<perms> <path>+0x<off>", or "UNMAPPED". The path is truncated by snprintf -- a diagnostic
 * only, so a short name is enough to tell libart from the boot image from the app's heap. */
static void wxr_describe(uint64_t va, char *out, size_t outlen)
{
    if (outlen == 0) return;
    out[0] = 0;
    if (va == 0) {
        snprintf(out, outlen, "(null)");
        return;
    }
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) {
        snprintf(out, outlen, "(maps unreadable)");
        return;
    }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        int k = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path);
        if (k < 2) continue;
        if (va < (uint64_t)lo || va >= (uint64_t)hi) continue;
        snprintf(out, outlen, "%s %s+0x%lx", (k >= 3) ? perms : "?", (k >= 4 && path[0]) ? path : "(anon)",
                 (unsigned long)(va - (uint64_t)lo));
        fclose(f);
        return;
    }
    fclose(f);
    snprintf(out, outlen, "UNMAPPED");
}

static void wxr_x0_report(void)
{
    uint64_t ring[WXR_X0_RING], idx, last, am, repl, entry, hits, misses;
    int track;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < WXR_X0_RING; i++) ring[i] = g_wxr_x0_ring[i];
    idx = g_wxr_x0_idx;
    last = g_wxr_x0_last;
    entry = g_wxr_entry;
    hits = g_wxr_hits;
    misses = g_wxr_misses;
    track = g_wxr_x0_track;
    struct wxr_table *t = (struct wxr_table *)g_wxr_active;
    /* The B.7.1 x0 question ("what is x0 actually?") is answered against the FIRST entry, which is
     * the one a single-method test run puts there. The full table is dumped by _dump(). */
    am = (t && t->count > 0) ? t->e[0].target : 0;
    repl = (t && t->count > 0) ? t->e[0].replacement : 0;
    pthread_mutex_unlock(&g_lock);

    char d[320], d2[320];
    wxr_describe(entry, d, sizeof d);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] x0 probe: the entry we armed (nterp_entry_point) = 0x%lx  [%s]",
                        (unsigned long)entry, d);
    wxr_describe(am, d, sizeof d);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] x0 probe: the table publishes        am = 0x%lx  [%s]",
                        (unsigned long)am, d);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] x0 probe:                            repl = 0x%lx   (a call whose "
                        "x0 matches `am` is redirected to this ArtMethod, entered through its OWN "
                        "entry point)", (unsigned long)repl);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] x0 probe: hits=%lu misses=%lu tracking=%d -- `misses` counts EVERY "
                        "interpreted call in this process",
                        (unsigned long)hits, (unsigned long)misses, track);

    if (misses == 0) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] x0 probe: NO MISSES RECORDED -- the router was NEVER ENTERED. "
                            "The armed page is not on the call path of any interpreted method in "
                            "this process, so x0 was never observed at all. Fixing the table or "
                            "the comparison cannot help; the dispatch point is the problem.");
        return;
    }

    int n = (idx < WXR_X0_RING) ? (int)idx : WXR_X0_RING;
    uint64_t start = (idx >= WXR_X0_RING) ? (idx % WXR_X0_RING) : 0;
    int has_am = 0, has_entry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t v = ring[(start + (uint64_t)i) % WXR_X0_RING];
        wxr_describe(v, d, sizeof d);
        char near[48] = "";
        if (am && v != am) {
            long long delta = (long long)(v - am);
            if (delta > -0x100000 && delta < 0x100000)
                snprintf(near, sizeof near, "  am%+lld", delta);
        }
        if (am && v == am) has_am = 1;
        if (entry && v == entry) has_entry = 1;
        (void)d2;
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "[wxr] x0 probe: %s[%d] = 0x%lx%s  [%s]%s",
                            (i == n - 1) ? "LAST " : "seen ", i, (unsigned long)v, near, d,
                            (am && v == am) ? "  <== EQUALS the published am: a hit SHOULD have fired"
                                            : "");
    }
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] x0 probe: last x0 = 0x%lx", (unsigned long)last);

    /* The verdict is ordered by what the data can actually settle. Note the ring holds MISSES
     * only -- a hit is not captured -- so `hits` is the evidence for "the comparison fired", and
     * a ring entry equal to `am` means "this value was seen and NOT matched", which is the only
     * way both can be true. */
    if (hits > 0)
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] x0 probe: VERDICT -- the comparison FIRED: hits=%lu. The table "
                            "and the x0 convention are working, so if the observed behaviour did "
                            "not change, x0 is not where the problem is: look DOWNSTREAM of the "
                            "swap (is the replacement ArtMethod actually invocable, and is this "
                            "call site one whose result is observable?).",
                            (unsigned long)hits);
    else if (has_am)
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] x0 probe: VERDICT -- x0 WAS the published am and still missed "
                            "(hits=0). The comparison is not the problem; the table the router "
                            "reads is not the table that was published.");
    else if (has_entry)
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] x0 probe: VERDICT -- x0 equals nterp_entry_point ITSELF. The "
                            "entry address is being passed in x0, so this entry's calling "
                            "convention is not `x0 = ArtMethod*` on this ART version.");
    else
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] x0 probe: VERDICT -- hits=0 and none of the last %d x0 values "
                            "was the published am. The method under test was therefore never "
                            "passed in x0 to this entry: either its calls do not reach this entry "
                            "point, or this ART passes something else in x0. The classification "
                            "above says what the values actually are; if one is at a small "
                            "am+/-delta it is a different ArtMethod of the same array (a callee, "
                            "or the unspecialized original).",
                            n);
}

static uint64_t wxr_prop_hex(const char *name)
{
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get(name, v) <= 0 || v[0] == '\0') return 0;
    return (uint64_t)strtoull(v, 0, 0); /* base 0: hex as logcat prints it, or decimal */
}

/* How many poll ticks (seconds) after the report is (re-)armed it is emitted. Non-zero so the
 * ring fills with the calls made after the interesting event -- arming, or a table publication --
 * rather than with whatever was running at that instant. */
#define WXR_X0_REPORT_TICKS 3

static void *wxr_poll_thread(void *arg)
{
    (void)arg;
    for (;;) {
        struct timespec ts;
        ts.tv_sec = 1;
        ts.tv_nsec = 0;
        while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        }
        pthread_mutex_lock(&g_lock);
        int live = g_wxr_poll_run && g_wxr_armed;
        /* The ONLY place g_wxr_poll_started is cleared, and it is cleared here because this
         * thread has now stopped publishing: a later re-arm may start a replacement poll, and
         * there is still exactly one writer of the table at any instant. */
        if (!live) g_wxr_poll_started = 0;
        pthread_mutex_unlock(&g_lock);
        if (!live) break;

        uint64_t t = wxr_prop_hex("persist.kpmhook.routerpoc.am");
        uint64_t r = wxr_prop_hex("persist.kpmhook.routerpoc.repl");
        uint64_t x = wxr_prop_hex("persist.kpmhook.routerpoc.x0");

        /* x0 diagnostic trigger. One shot, taken a couple of ticks after the last (re-)arm of
         * the report -- after a table publication that is the window worth sampling, because the
         * app's own calls to the target method are what fill the ring. `report` is acted on with
         * g_lock RELEASED: wxr_x0_report() opens /proc/self/maps and logs, neither of which
         * belongs inside the lock that hook installs also take. */
        int report = 0;
        pthread_mutex_lock(&g_lock);
        if (x != g_wxr_x0_prop) {
            g_wxr_x0_prop = x;
            g_wxr_x0_track = (x != 0);
            g_wxr_x0_logged = 0;
            g_wxr_x0_ticks = 0;
            pthread_mutex_unlock(&g_lock);
            __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                                "[wxr] x0 probe re-armed by property: tracking=%d (set "
                                "persist.kpmhook.routerpoc.x0 to 0 to stop capturing, or to any "
                                "other value to re-arm this report)",
                                x != 0);
            pthread_mutex_lock(&g_lock);
        }
        if (g_wxr_armed && g_wxr_x0_track && !g_wxr_x0_logged &&
            ++g_wxr_x0_ticks >= WXR_X0_REPORT_TICKS) {
            g_wxr_x0_logged = 1;
            report = 1;
        }
        pthread_mutex_unlock(&g_lock);
        if (report) {
            wxr_x0_report();
            continue; /* the table-update branch below is independent; fall through next tick */
        }

        pthread_mutex_lock(&g_lock);
        if (g_wxr_poll_run && g_wxr_armed && (t != g_wxr_seen_target || r != g_wxr_seen_repl)) {
            /* Remember the attempt even when it is rejected: a bad pair must not re-log every
             * second, and a later edit (am then repl) is still a change and still gets acted on. */
            g_wxr_seen_target = t;
            g_wxr_seen_repl = r;
            if ((t == 0) != (r == 0)) {
                __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                                    "[wxr] poll: only one of am/repl is set (am=0x%lx repl=0x%lx) "
                                    "-- NOT publishing; set both or clear both",
                                    (unsigned long)t, (unsigned long)r);
            } else if (!wxr_plausible(t, r)) {
                __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                                    "[wxr] poll: REFUSED am=0x%lx repl=0x%lx -- not a plausible "
                                    "ArtMethod pair for THIS process (a stale address from a "
                                    "previous launch looks like this); table unchanged",
                                    (unsigned long)t, (unsigned long)r);
            } else {
                /* The harness pair is ONE EXTRA ENTRY, never the whole table: the programmatic
                 * entries (added by kpm_wx_router_add from the hook path) are republished
                 * alongside it, so a test publication can never clobber a live hook. Clearing both
                 * properties therefore removes the harness entry only. */
                g_wxr_prop_on = (t != 0);
                g_wxr_prop_am = t;
                g_wxr_prop_repl = r;
                wxr_republish_locked();
                g_wxr_publishes++;
                /* Sample the x0 values that follow this publication: it is the moment the
                 * operator is about to drive the target method, so the ring fills with the calls
                 * that matter rather than with startup noise. */
                g_wxr_x0_logged = 0;
                g_wxr_x0_ticks = 0;
                __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                                    "[wxr] table PUBLISHED (harness pair) am=0x%lx repl=0x%lx%s "
                                    "(publication #%lu; table now holds %d programmatic + %d "
                                    "harness entry -- the router redirects every call whose "
                                    "ArtMethod* equals one of them to that entry's replacement)",
                                    (unsigned long)t, (unsigned long)r,
                                    t ? "" : " -- harness entry REMOVED",
                                    (unsigned long)g_wxr_publishes, g_wxr_prog_n,
                                    g_wxr_prop_on ? 1 : 0);
            }
        }
        pthread_mutex_unlock(&g_lock);
    }
    return 0;
}

/* Start the 1 Hz table poll. Called under g_lock, once, at arm time. A failure to create the
 * thread is NOT fatal: the router stays armed with the pair the arm was given (usually empty),
 * which is the pure miss-path state -- it just cannot be re-pointed, and it says so. */
static void wxr_poll_start_locked(void)
{
    if (g_wxr_poll_started) return;
    g_wxr_poll_started = 1;
    g_wxr_poll_run = 1;
    pthread_t th;
    if (pthread_create(&th, 0, wxr_poll_thread, 0) != 0) {
        g_wxr_poll_run = 0;
        g_wxr_poll_started = 0; /* no thread exists, so a later arm may try again */
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] table poll thread NOT started: the table can only be changed "
                            "by re-arming (the armed pair stays as it is)");
        return;
    }
    pthread_detach(th);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] table poll started (1 Hz): set persist.kpmhook.routerpoc.am / "
                        ".repl to this process's ArtMethod* at any time; clear both to empty the "
                        "table");
}

/* The replayed window + the branch back. Same relocation contract as wx_build_stub, with ONE
 * deliberate difference: the jump-back is built in x16 (IP0) rather than x17. The router's C
 * dispatch has already been unwound by the time this code runs, so x16 holds the caller's value
 * again -- and x16 is the register the final `br` is allowed to consume (see red line 4 above).
 * x17 is fully restored, so a covered instruction that carries x17 across the window keeps
 * working exactly as it did at the original address.
 * (wx_build_stub cannot be reused as-is: it hardcodes x17 for the resume, and it is on the live
 * B.2 path, so the two must not share an emitter whose register choice differs.) */
static int wxr_build_tail(uint64_t entry, uint64_t resume, uint32_t *out, int cap, const char **why)
{
    int n = 0;
    const uint32_t *in = (const uint32_t *)(uintptr_t)entry;
    uint64_t page = entry & ~(PAGE_SZ - 1);
    for (int i = 0; i < 4; i++) {
        int k = wx_reloc_insn(in[i], entry + (uint64_t)i * 4, page, out + n, cap - n, why);
        if (k < 0) return -1;
        n += k;
    }
    int k = wx_emit_mov64(out + n, cap - n, 16, resume);
    if (k < 0) { *why = "router tail overflow"; return -1; }
    n += k;
    if (cap - n < 1) { *why = "router tail overflow"; return -1; }
    out[n++] = WXR_BR_X16;
    return n;
}

/* The router itself: save -> C dispatch -> restore -> TWO exits.
 *
 *   MISS (x1 == 0): replay the covered window, then `movz/movk x16,#entry+16 ; br x16`. Byte-for-
 *                   byte the behaviour B.7.1 measured: x1..x17/x30/NZCV and SP all hold their entry
 *                   values -- x16 included, because the miss label reloads it from the frame before
 *                   the window runs -- so the shared stub continues as if nothing had run (red
 *                   line 4). The only x16 difference a caller can observe is the final branch
 *                   target, which is the allowed exception.
 *   HIT  (x1 == 1): pop the frame and `br replacement->entry_point_from_quick_compiled_code_`. The
 *                   router does NOT resume the shared stub with a rewritten x0 -- see the block
 *                   comment above ("WHY THE HIT PATH DOES NOT RESUME THE STUB").
 *
 * Both exits reach their branch with SP back at its entry value, x1..x15/x17/x30 and NZCV restored
 * from the frame (never the C dispatch's leftovers) and x0 = the dispatch result. Nothing here
 * reads the patched page (red line 3): the only addresses it touches are below SP, the table in
 * this library, and (on a hit) the replacement ArtMethod's entry-point field. */
static int wxr_build_router(uint64_t entry, uint32_t qc_off, uint32_t *out, int cap,
                            const char **why)
{
    int n = 0, cbz_at = -1;
    /* Word indices recorded while emitting, checked by the structural self-check at the end (see
     * there): the exact shape of the two exits is what the stack-walk argument rests on. */
    int hit_sp_at = -1, hit_movz_at = -1, hit_br_at = -1, miss_sp_at = -1;
    if (cap < 64) { *why = "router buffer too small"; return -1; }
    out[n++] = wxr_sub_sp(WXR_FRAME);
    out[n++] = wxr_stp_sp(1, 2, WXR_SLOT(1));
    out[n++] = wxr_stp_sp(3, 4, WXR_SLOT(3));
    out[n++] = wxr_stp_sp(5, 6, WXR_SLOT(5));
    out[n++] = wxr_stp_sp(7, 8, WXR_SLOT(7));
    out[n++] = wxr_stp_sp(9, 10, WXR_SLOT(9));
    out[n++] = wxr_stp_sp(11, 12, WXR_SLOT(11));
    out[n++] = wxr_stp_sp(13, 14, WXR_SLOT(13));
    out[n++] = wxr_stp_sp(15, 16, WXR_SLOT(15));
    out[n++] = wxr_stp_sp(17, 30, WXR_SLOT(17));
    out[n++] = WXR_MRS_NZCV_X16; /* x16 is already saved above, so this clobbers nothing live */
    out[n++] = wxr_str_sp(16, WXR_SLOT(19));
    { /* x16 = &wxr_dispatch (absolute; movz/movk, so no literal load anywhere near the entry) */
        int k = wx_emit_mov64(out + n, cap - n, 16, (uint64_t)(uintptr_t)&wxr_dispatch);
        if (k < 0) { *why = "router overflow materialising the dispatch address"; return -1; }
        n += k;
    }
    out[n++] = WXR_BLR_X16;
    /* Restore order matters twice over.
     *  - NZCV is reloaded THROUGH x16 first; x16 stops being available as scratch for the
     *    dispatch's result only after the `msr` below, which is why the hit flag (x1, the second
     *    register of the 16-byte struct return) is moved into x16 AFTER it and not before -- the
     *    nzcv reload would otherwise destroy it.
     *  - Every instruction from the msr down is flag-neutral (ldr/ldp/cbz/add without S do not
     *    write NZCV), so the caller's condition flags reach the replayed window intact.
     * At the `cbz` below, SP and x1..x15/x17/x30 and NZCV all hold their entry values, x0 holds
     * the dispatch result (the point of the whole router) and x16 holds the hit flag. x16 is the
     * one register the router is allowed to consume for its own bookkeeping: it is IP0, scratch at
     * an indirect call by ABI, and it is the register the existing, device-verified backend
     * already clobbers at this very entry (wx_patch_bytes). */
    out[n++] = wxr_ldr_sp(16, WXR_SLOT(19));
    out[n++] = WXR_MSR_NZCV_X16;
    out[n++] = WXR_MOV_X16_X1;
    out[n++] = wxr_ldp_sp(17, 30, WXR_SLOT(17)); /* x30 (the return address) comes back here */
    out[n++] = wxr_ldr_sp(15, WXR_SLOT(15));     /* x15 only: x16 carries the hit flag */
    out[n++] = wxr_ldp_sp(13, 14, WXR_SLOT(13));
    out[n++] = wxr_ldp_sp(11, 12, WXR_SLOT(11));
    out[n++] = wxr_ldp_sp(9, 10, WXR_SLOT(9));
    out[n++] = wxr_ldp_sp(7, 8, WXR_SLOT(7));
    out[n++] = wxr_ldp_sp(5, 6, WXR_SLOT(5));
    out[n++] = wxr_ldp_sp(3, 4, WXR_SLOT(3));
    out[n++] = wxr_ldp_sp(1, 2, WXR_SLOT(1));
    /* x16 == 0 -> miss -> the replayed window (forward branch, patched below). `cbz` reads x16 and
     * clobbers nothing, so the flag survives into the two exits. */
    cbz_at = n;
    out[n++] = wxr_cbz_x16(0); /* imm19 patched once the miss label's index is known */
    /* HIT. Release the router frame FIRST: this exit branches (tail-calls) rather than returning,
     * so SP must be back at its entry value before `br` -- exactly like the miss exit below, and
     * exactly what ART's own trampolines do. Leaving the frame live here is not a stack leak that
     * merely wastes 160 bytes: it puts a frame ART can SEE but cannot UNDERSTAND into the frame
     * chain of the replacement's execution. ART walks a quick frame by reading the frame's
     * ArtMethod from `*frame_base` and advancing to the caller at `frame_base +
     * that_method's_code_size` (that is why the reference has to write a fake OatQuickMethodHeader
     * and the caller's LR at `frame_base + frame_size - 8` -- see the block comment). With this
     * frame left on the stack, `replacement_frame_base + code_size(replacement)` lands EXACTLY on
     * the router frame's base, which is slot 0 -- deliberately never written (see WXR_FRAME) -- so
     * the walker reads whatever dead stack happened to be below the caller's SP as an ArtMethod and
     * continues into garbage: a mis-attributed frame during a GC/checkpoint/deopt (wrong roots,
     * wrong objects) or a wild branch, on the first stack walk that happens while a routed method
     * is on the stack -- which during dex injection/class loading it constantly is.
     * NOTE the asymmetry with the reference, which KEEPS its frame: its thunk IS the method the
     * caller called (its ArtMethod entry point is the thunk), so its frame is a real one that only
     * needs a valid method slot ("publish `replacement` at SP+0", a native method so GetDexPc
     * early-exits) plus a fake OAT header for its PC. Ours is not: the routed method the caller
     * called is `target`, whose frame is the REPLACEMENT's own, entered through ART's own entry for
     * it. A router frame here is a frame between two real ones, which ART never sees on the miss
     * path (it is popped) and must not see here either -- so the fix is to remove it, not to make
     * it look valid: a single valid method slot would still be paired with a frame size ART derives
     * from that method's code, which is not this frame's size.
     * `add sp, sp, #imm` (S=0) writes no NZCV and touches no register, so the caller's flags -- and
     * x0 (the replacement) and x16 (still the hit flag) -- are unaffected. */
    out[n++] = wxr_add_sp(WXR_FRAME);
    hit_sp_at = n - 1;
    /* x16 != 0 -> hit -> x16 = replacement->entry_point_from_quick_compiled_code_ -> enter it.
     * x0 is already the replacement ArtMethod*, SP and every other register are the caller's, so
     * this is a plain tail call into ART's own entry for that method. */
    hit_movz_at = n;
    out[n++] = wxr_movz_x16(qc_off);
    out[n++] = WXR_LDR_X16_X0_X16;
    hit_br_at = n;
    out[n++] = WXR_BR_X16;
    /* MISS label: put the CALLER's x16 back and pop the frame, then replay the covered window +
     * `movz/movk x16,#entry+16 ; br x16`. The x16 reload is what makes the replayed window see the
     * exact register state the unpatched entry would have seen -- the router's own use of x16 (the
     * hit flag) leaves no trace on the miss path at all, so the only x16 difference a caller can
     * observe is the final branch target, i.e. the allowed exception of red line 4. */
    int miss_at = n;
    out[n++] = wxr_ldr_sp(16, WXR_SLOT(16));
    out[n++] = wxr_add_sp(WXR_FRAME);
    miss_sp_at = n - 1;
    int k = wxr_build_tail(entry, entry + 16, out + n, cap - n, why);
    if (k < 0) return -1;
    n += k;
    out[cbz_at] = wxr_cbz_x16((unsigned)(miss_at - cbz_at));
    /* STRUCTURAL SELF-CHECK (fail-closed, so this can never regress silently): the invariant both
     * exits depend on is "the router frame is released before the branch" -- the hit exit because
     * ART's stack walk would otherwise enter a frame whose method slot was never written (see the
     * hit-path comment above), the miss exit because red line 4 requires the miss path to be
     * indistinguishable from the unpatched entry. So assert, ON THE EMITTED WORDS, that the
     * release still sits immediately before each exit's branch sequence (and that the frame
     * allocation is still word 0): this catches a future edit that drops or reorders the release,
     * and a wrong label index, since the `cbz` backpatch below writes into the stream too. A
     * router that fails this is not armed at all -- the arm path treats it like any other refusal
     * and the caller falls back to the in-place hook, which is detectable but correct. */
    if (out[0] != wxr_sub_sp(WXR_FRAME) ||                                    /* one frame ... */
        out[hit_sp_at] != wxr_add_sp(WXR_FRAME) || hit_sp_at + 1 != hit_movz_at ||
        out[hit_movz_at] != wxr_movz_x16(qc_off) || out[hit_br_at] != WXR_BR_X16 ||
        out[miss_sp_at] != wxr_add_sp(WXR_FRAME)) {                           /* ... two releases */
        *why = "router shape: the release sequence at one of the two exits is not the shape this "
               "router's stack-walk argument requires (hit exit: add sp / movz / ldr / br; miss "
               "exit: ldr x16 / add sp / replayed window / movz,movk / br)";
        return -1;
    }
    return n;
}

/* Arm the shared-stub router on `entry`. Called with g_lock HELD. See the contract in kpmhook.h;
 * every refusal below is fail-closed (nothing armed, nothing half-written) and names its reason in
 * logcat. Returns 0 on success, -1 after logging on refusal.
 *
 * ONCE PER PROCESS. The patched page's shadow bytes are immutable (the KPM has no "re-patch"), so
 * a second arm cannot be honoured; a method that wants to route onto an ALREADY armed router goes
 * through kpm_wx_router_add, which only extends the table. `start_poll` starts the 1 Hz property
 * thread -- only the B.7.1 harness wants it (see wxr_poll_start_locked); the hook path does not,
 * because the table it installs is maintained by the caller, not by a property. */
static int wxr_arm_locked(uint64_t entry, int start_poll, uint32_t qc_off)
{
    int rc = -1, n = 0, idx = -1, slot = -1, self_reads = 0, mode = WX_MODE_FLIP;
    const char *why = 0;
    uint64_t page = 0, off = 0, stub = 0;
    uint32_t words[WXR_MAX_WORDS];

    if (ensure_init_locked() != 0) {
        why = "bridge off or this process is not gated";
        goto refuse;
    }
    /* Red line 2: the caller resolves the entry from ART's symbols. We still refuse a null (or
     * misaligned) one here -- a caller that silently forgot must not arm address 0. */
    if (entry < 0x2000 || (entry & 3)) {
        why = "entry is null / implausible / not 4-byte aligned (resolve it from ART's symbols)";
        goto refuse;
    }
    /* The hit path reads `replacement->entry_point_from_quick_compiled_code_` and branches to it,
     * so the router cannot be built without that field's offset. It is a small, pointer-sized,
     * pointer-aligned slot inside an ArtMethod: anything else is a caller that has not resolved it
     * from ART's own layout, and arming on a wrong offset would branch into a non-code field.
     * FAIL-CLOSED, and before any resource is committed. */
    if (qc_off == 0 || (qc_off & 7) || qc_off > 4096) {
        __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                            "[wxr] REFUSED shared entry=0x%lx -> NOT armed. reason: the ArtMethod "
                            "entry-point offset is 0x%x, which is not a plausible pointer field "
                            "offset (it must come from ART's own ArtMethod layout, e.g. LSPlant's "
                            "ArtMethod::GetEntryPointOffset -- never a hardcoded constant). The hit "
                            "path needs it to enter the replacement through ITS OWN entry point",
                            (unsigned long)entry, qc_off);
        goto refuse;
    }
    if (g_wxr_armed) {
        /* The shadow page's bytes are immutable once armed (the KPM has no "re-patch"), so a
         * second arm with a different router cannot be honoured. Refuse rather than pretend. */
        why = "the shared-stub router is already armed (one arm per process; disarm first)";
        goto refuse;
    }
    page = entry & ~(PAGE_SZ - 1);
    off = entry - page;
    if (off + 16 > PAGE_SZ) {
        why = "the 16-byte patch would cross the page";
        goto refuse;
    }
    /* Red line 1, before ANY resource is committed (no stub slot, no ghost VA, no patch). An R^X
     * shadow page is a SNAPSHOT, so a page ART keeps writing is a crash, not a trade-off.
     * libart.so is the opposite (P3) -- but the guard is unconditional, because the entry is a
     * parameter and a future caller could pass anything. */
    if (wx_page_is_jit(page)) {
        why = "the shared-stub page is ART's JIT code cache (or is not classifiable as non-JIT "
              "code): an R^X shadow page is a snapshot of a page ART keeps writing (SIGILL)";
        goto refuse;
    }
    if (wx_find_qc_locked(entry) || wx_find_page_locked(page)) {
        why = "this entry (or its page) already carries a WX patch";
        goto refuse;
    }

    /* Red line 3, part 1 -- can the covered window be relocated at all? wx_reloc_insn answers
     * this inside wxr_build_tail, but the ANSWER has to be visible: it is one of B.7.1's
     * acceptance questions, and a bare "refused, in-place fallback" would hide it. So the four
     * words are inspected and logged here, with the same predicates the relocation uses, and a
     * PC-relative covered instruction -- which includes LDR/PRFM (literal), i.e. a literal load
     * that could name this same page -- refuses the arm outright. */
    {
        const uint32_t *in = (const uint32_t *)(uintptr_t)entry;
        for (int i = 0; i < 4; i++) {
            uint64_t val = 0;
            const char *kind = "verbatim (position-independent)";
            if (wx_adr_value(in[i], entry + (uint64_t)i * 4, &val)) {
                if (val >= page && val < page + PAGE_SZ) {
                    __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                                        "[wxr] covered insn %d: %08x is an ADR/ADRP resolving to "
                                        "0x%lx, INSIDE the patched page -- refusing to arm (red "
                                        "line 3: a consumer would read the execute-only shadow "
                                        "view)",
                                        i, in[i], (unsigned long)val);
                    why = "a covered instruction is an ADR/ADRP resolving into the patched page";
                    goto refuse;
                }
                kind = "ADR/ADRP -> rebuilt as movz/movk x<rd>,#value";
            } else if (wx_is_pc_rel(in[i])) {
                __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                                    "[wxr] covered insn %d: %08x is PC-relative "
                                    "(B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/LDR-literal/PRFM-literal) and "
                                    "cannot be expressed in the 16-byte window -- refusing to arm",
                                    i, in[i]);
                why = "a covered instruction is PC-relative (not relocatable in 16 bytes)";
                goto refuse;
            }
            __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                                "[wxr] covered insn %d: %08x  %s", i, in[i], kind);
        }
    }

    /* Red line 3, part 2 -- the rest of the stub's body still executes from the shadow page, so
     * the FLIP/RX decision is the same B.6 one the per-method WX path makes. A body that reads
     * its own page would livelock under FLIP, so it selects RX (which gives up read-hiding on
     * this page); everything else keeps FLIP, and read-hiding with it. */
    self_reads = wx_body_reads_own_page(entry, page);
    mode = self_reads ? WX_MODE_RX : WX_MODE_FLIP;

    /* Publish the starting table BEFORE the patch exists. The router cannot be reached until
     * wx_patch_locked has published the patch, and wxr_republish_locked's release store is what
     * orders the table against that -- so the first routed call already sees a consistent table.
     * At arm time the table is usually EMPTY: the caller's ArtMethod* for THIS process does not
     * exist yet (the hook path adds it a moment later, the B.7.1 harness installs its test pair
     * through the 1 Hz poll). */
    g_wxr_hits = 0;
    g_wxr_misses = 0;
    g_wxr_publishes = 0;
    for (int i = 0; i < WXR_ALL_ENTRIES; i++) g_wxr_slot_hits[i] = 0;
    g_wxr_seen_target = 0; /* so the poll acts on the first value it reads, not on a change */
    g_wxr_seen_repl = 0;
    for (int i = 0; i < WXR_X0_RING; i++) g_wxr_x0_ring[i] = 0;
    g_wxr_x0_idx = 0;
    g_wxr_x0_last = 0;
    g_wxr_x0_track = 1;
    g_wxr_x0_logged = 0;
    g_wxr_x0_ticks = 0;
    g_wxr_x0_prop = 0; /* matches the "no property set" state, so no spurious re-arm log */
    wxr_republish_locked();

    g_wxr_qc_off = qc_off;
    n = wxr_build_router(entry, qc_off, words, (int)(sizeof words / sizeof words[0]), &why);
    if (n < 0) goto refuse;

    for (int i = 0; i < WX_MAX_PAGES; i++)
        if (!g_wxents[i].used) { idx = i; break; }
    if (idx < 0) { why = "wx table full"; goto refuse; }

    /* The router gets its own VMA-less ghost page (B.4), templated on the shared stub's own page
     * so it is mapped exactly like real code. Nothing to hide: a published ghost VA has no VMA,
     * so it is absent from maps/smaps/mincore with no hide-set entry. Being a different VA is
     * also what keeps red line 3 satisfied by construction: the router's own code, its stack
     * frame and its table are all outside the patched page, so nothing it does can fault on the
     * execute-only shadow view. */
    stub = wx_stub_publish_locked(words, n, page);
    if (!stub) {
        why = "router publish failed (ghost VA taken / wxstub rejected / stub pool exhausted)";
        goto refuse;
    }
    uint8_t patch[16];
    if (wx_patch_bytes(stub, patch) != 0) {
        why = "the router VA needs more than 48 bits";
        goto refuse;
    }
    if (wx_patch_locked(entry, patch, &slot, mode) != 0) {
        why = "wxpatch rejected (see the reply in the [wx] arm line above)";
        goto refuse;
    }
    g_wxents[idx].used = 1;
    g_wxents[idx].qc = entry;
    g_wxents[idx].page = page;
    g_wxents[idx].off = off;
    g_wxents[idx].stub = stub;
    g_wxents[idx].slot = slot;
    g_wxents[idx].mode = mode;
    g_wxents[idx].router = 1; /* NOT a per-method shadow page: only the router may release it */
    g_wxr_entry = entry;
    g_wxr_router = stub;
    g_wxr_mode = mode;
    g_wxr_self_reads = self_reads;
    g_wxr_armed = 1;
    rc = 0;
    /* The router is live from here. The B.7.1 harness wants the 1 Hz poll (it is the only way a
     * property can reach the table); the hook path does not. */
    if (start_poll) wxr_poll_start_locked();
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] ARMED shared entry=0x%lx (page=0x%lx off=0x%lx) shadow slot=%d "
                        "mode=%s%s -> router 0x%lx (%d insns, VMA-less ghost page); ArtMethod "
                        "entry-point offset=0x%x (the hit path reads replacement->entry_point_ "
                        "from it); table now "
                        "holds %d routed method(s)%s. NOW GLOBAL: every interpreted call in this "
                        "process runs through the router; a method not in the table must behave "
                        "exactly as it did before (miss path).",
                        (unsigned long)entry, (unsigned long)page, (unsigned long)off, slot,
                        (mode == WX_MODE_RX) ? "RX" : "FLIP",
                        self_reads ? " (body reads its own page: read-hiding given up ON THIS "
                                     "PAGE; reads of the patched 16 bytes show the patch)"
                                   : "",
                        (unsigned long)stub, n, (unsigned)qc_off, g_wxr_prog_n,
                        g_wxr_prog_n == 0 ? " (EMPTY at arm time -- the caller installs its entry "
                                            "next; nothing is routed until then)"
                                          : "");
    /* The ONE property of the emitted code that the hit path's correctness rests on, stated where
     * an operator will look for it. The hit exit is a TAIL call, so the frame must be gone before
     * it branches: if it were left live, `replacement_frame_base + code_size(replacement)` (how
     * ART advances a frame chain -- it reads the frame's ArtMethod from `*frame_base`) lands on
     * the router frame's base, whose slot 0 is never written, and the walk continues with garbage
     * (see the hit path in wxr_build_router). wxr_build_router refuses to emit a router whose exits
     * do not release it, so this line is not a hope: it is the check having passed. The word dump
     * below is the same fact in raw form (`add sp, sp, #160` = 0x910283ff appears once per exit). */
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] router exits: BOTH paths release the router frame before branching "
                        "(miss: replay covered window -> entry+16; hit: SP restored -> br "
                        "replacement->entry_point_from_quick_compiled_code_), so no frame of ours is "
                        "ever in ART's frame chain -- the same stack-walk shape as the miss path.");
    /* Dump the emitted router so the exact instruction stream is recoverable from logcat alone
     * -- the acceptance question "what does the router do, and what does it touch" should be
     * answerable without a debugger, and a wrong encoder bit is visible here before it is a
     * crash inside the interpreter. */
    for (int i = 0; i < n; i += 8) {
        char hex[8 * 9 + 1];
        int p = 0;
        for (int j = i; j < n && j < i + 8; j++)
            p += snprintf(hex + p, sizeof(hex) - (size_t)p, "%08x ", words[j]);
        if (p > 0) hex[p - 1] = 0;
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG, "[wxr] router[%3d] %s", i, hex);
    }
    return rc;

refuse:
    __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                        "[wxr] REFUSED shared entry=0x%lx -> NOT armed. reason: %s",
                        (unsigned long)entry, why ? why : "unknown");
    /* Nothing is published here: a refusal must not empty or alter the table of a router that is
     * already live (the caller that owns the publish restores its own model). */
    return rc;
}

/* The B.7.1 POC's arm entry point: arm the router once and install {target_am, replacement_am} as
 * the table's EXTRA harness entry. Kept because it is the mechanism test -- `kpm_wx_router_poc_arm
 * (entry, 0, 0)` arms with an EMPTY table, which is the red-line-4 miss-path test (every
 * interpreted call in the process must behave exactly as before). The hook path uses
 * kpm_wx_router_add instead, and the two compose: whichever arms first, the other only extends or
 * replaces its own entries. */
int kpm_wx_router_poc_arm(uint64_t entry, uint64_t target_am, uint64_t replacement_am,
                          uint32_t quickcode_offset)
{
    int rc = -1;
    int old_on;
    uint64_t old_am, old_repl;

    pthread_mutex_lock(&g_lock);
    if ((target_am == 0) != (replacement_am == 0)) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] REFUSED arm: target and replacement must be given together "
                            "(0/0 = arm with an empty table)");
        goto out;
    }
    old_on = g_wxr_prop_on;
    old_am = g_wxr_prop_am;
    old_repl = g_wxr_prop_repl;
    /* Install the harness pair in the MODEL first, so the arm's own publish already carries it --
     * the router must never be reachable with a table that disagrees with the caller's intent. */
    g_wxr_prop_on = (target_am != 0);
    g_wxr_prop_am = target_am;
    g_wxr_prop_repl = replacement_am;
    if (wxr_arm_locked(entry, /*start_poll=*/1, quickcode_offset) != 0) {
        /* The refusal was logged with its reason; put the model back exactly as it was. */
        g_wxr_prop_on = old_on;
        g_wxr_prop_am = old_am;
        g_wxr_prop_repl = old_repl;
        wxr_republish_locked();
        goto out;
    }
    rc = 0;
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] harness pair published am=0x%lx repl=0x%lx%s -- this is the table's "
                        "EXTRA entry (B.7.1 test path); %d programmatic entry/entries from the "
                        "hook path are unaffected by it",
                        (unsigned long)target_am, (unsigned long)replacement_am,
                        target_am ? "" : " -- EMPTY: every interpreted call must take the miss "
                                         "path and behave exactly as before",
                        g_wxr_prog_n);
out:
    pthread_mutex_unlock(&g_lock);
    return rc;
}

/* Route one ArtMethod onto the ALREADY armed (or freshly armed) shared-stub router: a call that
 * reaches `entry` with x0 == target_am is redirected to `replacement_am`, which a hit ENTERS
 * THROUGH ITS OWN ENTRY POINT -- `*(void **)(replacement_am + quickcode_offset)`, i.e. the entry
 * ART itself would use for it (see "WHY THE HIT PATH DOES NOT RESUME THE STUB" above). This is the
 * whole of B.7.2's write side, and it is the ONLY thing the hook path does -- `target_am`'s
 * ArtMethod is never written, which is the point of the exercise.
 *
 * `entry` is the shared stub's address as RESOLVED FROM ART'S SYMBOLS by the caller (red line 5:
 * eligibility is a symbol comparison, never a code-size heuristic). This function checks that the
 * entry it is handed agrees with the one already armed, and that it is a sane, non-JIT code
 * address, but it cannot know that the value is nterp -- the caller owns that decision.
 * `quickcode_offset` likewise comes from the caller's ART layout knowledge (LSPlant's
 * ArtMethod::GetEntryPointOffset()); it is validated here (non-zero, pointer-aligned, small) and
 * must match the one the router was armed with, because the armed router has it baked in.
 *
 * Every refusal is fail-closed and named: the caller falls back to its in-place path. */
int kpm_wx_router_add(uint64_t entry, uint64_t target_am, uint64_t replacement_am,
                      uint32_t quickcode_offset)
{
    int rc = -1, at = -1;

    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] add REFUSED target=0x%lx -> in-place fallback. reason: bridge "
                            "off or this process is not gated",
                            (unsigned long)target_am);
        goto out;
    }
    if (entry < 0x2000 || (entry & 3)) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] add REFUSED target=0x%lx entry=0x%lx -> in-place fallback. "
                            "reason: the shared entry is null / implausible / not 4-byte aligned "
                            "(it must be resolved from ART's symbols)",
                            (unsigned long)target_am, (unsigned long)entry);
        goto out;
    }
    if (target_am == 0 || replacement_am == 0) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] add REFUSED -> in-place fallback. reason: a null ArtMethod "
                            "(target=0x%lx replacement=0x%lx); the router must never be told to "
                            "redirect a call to or from null",
                            (unsigned long)target_am, (unsigned long)replacement_am);
        goto out;
    }
    if (target_am == replacement_am) {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] add REFUSED target=0x%lx -> in-place fallback. reason: the "
                            "replacement IS the target, i.e. a hook that would redirect a call "
                            "to the method it is already calling; that is not a hook",
                            (unsigned long)target_am);
        goto out;
    }
    /* NO ROUTED METHOD MAY BE THE REPLACEMENT OF ANOTHER. The hit path leaves the shared stub and
     * branches to the replacement's own entry point; when that entry IS the armed shared stub (the
     * normal case for an interpreted hook method), the router is entered a second time with
     * x0 == replacement. If the replacement were itself a table target that second pass would be a
     * HIT and branch again -- i.e. the table would be a graph with a cycle and the router would
     * loop forever on that method, inside a global interpreter entry point where a hang is worse
     * than any refusal. A chain of length 2 is the shortest possible cycle, so refusing "the
     * replacement is already a routed target" removes every cycle at once and the re-entry always
     * terminates: a hit either runs the replacement's OWN entry or misses and interprets it. */
    for (int i = 0; i < g_wxr_prog_n; i++)
        if (g_wxr_prog[i].target == replacement_am) {
            __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                                "[wxr] add REFUSED target=0x%lx -> in-place fallback. reason: the "
                                "replacement 0x%lx is ITSELF a routed target (table entry #%d). "
                                "Chaining one routed method onto another would let the router "
                                "re-enter itself without bound (the hit path branches to the "
                                "replacement's own entry, which is this shared entry for an "
                                "interpreted method); the table must stay acyclic",
                                (unsigned long)target_am, (unsigned long)replacement_am, i);
            goto out;
        }
    for (int i = 0; i < g_wxr_prog_n; i++)
        if (g_wxr_prog[i].target == target_am) {
            at = i;
            break;
        }
    /* Capacity is checked BEFORE the arm, so a fresh arm can never leave a router armed for a
     * method it then refuses to route. A re-add of an entry that is already there needs no room. */
    if (at < 0 && g_wxr_prog_n >= WXR_MAX_ENTRIES) {
        g_wxr_prog_full++;
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "[wxr] add REFUSED target=0x%lx -> in-place fallback. reason: the "
                            "router table is FULL (%d entries, cap %d); %d add(s) refused so far. "
                            "FAIL-CLOSED: the method keeps the in-place hook rather than sharing "
                            "the router's page budget",
                            (unsigned long)target_am, g_wxr_prog_n, WXR_MAX_ENTRIES,
                            g_wxr_prog_full);
        goto out;
    }
    if (g_wxr_armed) {
        if (g_wxr_entry != entry) {
            __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                                "[wxr] add REFUSED target=0x%lx -> in-place fallback. reason: the "
                                "router is armed on a DIFFERENT shared entry (0x%lx, asked for "
                                "0x%lx). One W^X patch per page and one live arm per process: a "
                                "second shared entry cannot be armed",
                                (unsigned long)target_am, (unsigned long)g_wxr_entry,
                                (unsigned long)entry);
            goto out;
        }
        if (g_wxr_qc_off != quickcode_offset) {
            __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                                "[wxr] add REFUSED target=0x%lx -> in-place fallback. reason: the "
                                "router is armed with ArtMethod entry-point offset 0x%x but this "
                                "call asks for 0x%x. The offset is a property of ART's ArtMethod "
                                "layout, so a disagreement means one of the two callers resolved "
                                "it wrongly; the armed router cannot be rebuilt (the shadow bytes "
                                "are immutable)",
                                (unsigned long)target_am, (unsigned)g_wxr_qc_off,
                                (unsigned)quickcode_offset);
            goto out;
        }
    } else if (wxr_arm_locked(entry, /*start_poll=*/0, quickcode_offset) != 0) {
        goto out; /* the arm logged the exact reason (bridge, JIT page, covered insn, KPM reject) */
    }
    if (at < 0) {
        at = g_wxr_prog_n++;
        g_wxr_prog_added++;
    } else {
        g_wxr_prog_upd++;
    }
    g_wxr_prog[at].target = target_am;
    g_wxr_prog[at].replacement = replacement_am;
    g_wxr_slot_hits[at] = 0; /* the slot's counter belongs to the new occupant now */
    wxr_republish_locked();
    g_wxr_publishes++;
    rc = 0;
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] ROUTED target=0x%lx -> replacement 0x%lx via shared entry 0x%lx "
                        "(table entry #%d, %d routed, %d update(s), %d add(s) total). The target "
                        "ArtMethod is NOT written: a call arriving at the shared entry with "
                        "x0 == target is redirected to the replacement, which the router ENTERS "
                        "THROUGH ITS OWN entry point ([replacement + 0x%x] -- how ART itself "
                        "enters that method, be it nterp, the interpreter bridge, JIT code or a "
                        "JNI trampoline), with the caller's quick-ABI registers restored. A "
                        "call-original reaches the backup ArtMethod instead, whose ArtMethod* is a "
                        "MISMATCH here and therefore runs the original through the untouched "
                        "interpreter path",
                        (unsigned long)target_am, (unsigned long)replacement_am,
                        (unsigned long)entry, at, g_wxr_prog_n, g_wxr_prog_upd,
                        g_wxr_prog_added, (unsigned)g_wxr_qc_off);
out:
    pthread_mutex_unlock(&g_lock);
    return rc;
}

/* Stop routing `target_am`: the entry is dropped from the table and the router stops matching it,
 * so calls to it run the original code again. Returns 1 if it was routed, 0 if it was not (which
 * is NOT an error -- the caller uses it to decide whether the router owned this method).
 *
 * The ARM IS LEFT IN PLACE. The patch belongs to the shared entry, not to this method: releasing it
 * would unhook every other routed method of the process at once, and re-arming is impossible (the
 * shadow bytes are immutable). The cost of leaving it is the router's per-call dispatch, which is
 * what a MISS costs anyway -- device-measured as a no-op (P3). */
int kpm_wx_router_remove(uint64_t target_am)
{
    int ok = 0, found = -1;

    pthread_mutex_lock(&g_lock);
    if (!g_inited || target_am == 0) goto out;
    for (int i = 0; i < g_wxr_prog_n; i++)
        if (g_wxr_prog[i].target == target_am) {
            found = i;
            break;
        }
    if (found < 0) goto out; /* not routed by the router */
    for (int i = found + 1; i < g_wxr_prog_n; i++) g_wxr_prog[i - 1] = g_wxr_prog[i];
    g_wxr_prog_n--;
    memset(&g_wxr_prog[g_wxr_prog_n], 0, sizeof(g_wxr_prog[0]));
    g_wxr_prog_removed++;
    wxr_republish_locked();
    g_wxr_publishes++;
    ok = 1;
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] UNROUTED target=0x%lx (table now %d routed; %d removal(s)). The "
                        "shared entry STAYS armed -- the patch is shared by every routed method, "
                        "so it cannot be released per method; the router simply no longer matches "
                        "this ArtMethod and its calls take the (behaviourally identical) miss path",
                        (unsigned long)target_am, g_wxr_prog_n, g_wxr_prog_removed);
out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

/* Release the patch and empty the table. A failed wxrelease leaves the patch LIVE and the state
 * UNCHANGED -- reporting success while the router still runs would be a lie (same rule as
 * kpm_wx_java_unhooker). */
int kpm_wx_router_poc_disarm(void)
{
    int ok = 0;
    pthread_mutex_lock(&g_lock);
    if (!g_inited || !g_wxr_armed) goto out;
    {
        struct wxent *e = wx_find_qc_locked(g_wxr_entry);
        if (e && e->slot >= 0) {
            char cmd[64], out[192];
            snprintf(cmd, sizeof cmd, "wxrelease %d", e->slot);
            bridge_cmd(cmd, out, sizeof out);
            __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                                "[wxr] release entry=0x%lx slot=%d reply=[%s]",
                                (unsigned long)g_wxr_entry, e->slot, out);
            if (!reply_ok(out)) goto out; /* patch still live: keep the state truthful */
        }
        if (e) memset(e, 0, sizeof(*e));
    }
    g_wxr_poll_run = 0;      /* the poll thread observes this within its 1 s sleep */
    /* Disarm takes the whole table with it: the patch is gone, so every entry in it is dead. */
    g_wxr_prog_n = 0;
    g_wxr_prop_on = 0;
    g_wxr_prop_am = 0;
    g_wxr_prop_repl = 0;
    wxr_republish_locked();
    g_wxr_armed = 0;
    ok = 1;
out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

int kpm_wx_router_poc_stats(struct kpm_wx_router_stats *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_lock);
    struct wxr_table *t = (struct wxr_table *)g_wxr_active;
    out->armed = g_wxr_armed;
    out->entry = g_wxr_entry;
    out->router = g_wxr_router;
    out->mode = (uint64_t)g_wxr_mode;
    out->self_reads = (uint64_t)g_wxr_self_reads;
    /* The single-pair fields report the FIRST entry of the live table (the common one-hook case,
     * and the one the B.7.1 x0 probe is written against). The whole table is in the log line
     * kpm_wx_router_poc_dump() prints below. */
    out->target = (t && t->count > 0) ? t->e[0].target : 0;
    out->replacement = (t && t->count > 0) ? t->e[0].replacement : 0;
    out->entries = t ? t->count : 0;
    out->routed = (uint64_t)g_wxr_prog_n;
    out->added = (uint64_t)g_wxr_prog_added;
    out->removed = (uint64_t)g_wxr_prog_removed;
    out->refused_full = (uint64_t)g_wxr_prog_full;
    out->updated = (uint64_t)g_wxr_prog_upd;
    out->hits = g_wxr_hits;
    out->misses = g_wxr_misses;
    out->publishes = g_wxr_publishes;
    out->polling = (uint64_t)(g_wxr_poll_started && g_wxr_poll_run);
    out->x0_last = g_wxr_x0_last; /* the most recent x0 the router saw (diagnostic) */
    for (int i = 0; i < WXR_ALL_ENTRIES; i++) out->slot_hits[i] = g_wxr_slot_hits[i];
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void kpm_wx_router_poc_dump(void)
{
    struct kpm_wx_router_stats s;
    if (kpm_wx_router_poc_stats(&s) != 0) return;
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "[wxr] stat armed=%lu entry=0x%lx router=0x%lx mode=%s self_reads=%lu "
                        "entries=%lu routed=%lu added=%lu updated=%lu removed=%lu refused_full=%lu "
                        "hits=%lu misses=%lu poll=%lu publications=%lu x0_last=0x%lx",
                        (unsigned long)s.armed, (unsigned long)s.entry, (unsigned long)s.router,
                        (s.mode == WX_MODE_RX) ? "RX" : "FLIP", (unsigned long)s.self_reads,
                        (unsigned long)s.entries, (unsigned long)s.routed, (unsigned long)s.added,
                        (unsigned long)s.updated, (unsigned long)s.removed,
                        (unsigned long)s.refused_full, (unsigned long)s.hits,
                        (unsigned long)s.misses, (unsigned long)s.polling,
                        (unsigned long)s.publishes, (unsigned long)s.x0_last);
    /* One line per routed method, with its own hit count. This is the B.7.2 coverage answer: which
     * methods the router took over, and which of them actually took a hit. */
    for (int i = 0; i < (int)s.routed; i++)
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "[wxr] stat   entry[%d] target=0x%lx -> replacement=0x%lx hits=%lu",
                            i, (unsigned long)g_wxr_prog[i].target,
                            (unsigned long)g_wxr_prog[i].replacement,
                            (unsigned long)s.slot_hits[i]);
    if (s.entries > s.routed)
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "[wxr] stat   entry[%lu] (B.7.1 harness pair) hits=%lu",
                            (unsigned long)s.routed, (unsigned long)s.slot_hits[s.routed]);
}

/* Register an anomalous region (page containing `addr`) with the KPM's mm-gated maps-hide,
 * so an in-process /proc/self/{maps,smaps} scan never sees it -- chiefly the LSPlant trampoline
 * pool (rwxp anon) that every hook creates. Only works in the gated process (bridge armed). */
int kpm_hide_region(void *addr)
{
    int ok = 0;
    pthread_mutex_lock(&g_lock);
    if (ensure_init_locked() != 0) goto out;
    char cmd[96], out[160];
    snprintf(cmd, sizeof cmd, "hidergn %d 0x%lx", g_pid, (unsigned long)(uintptr_t)addr);
    bridge_cmd(cmd, out, sizeof out);
    ok = reply_ok(out);
out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

/* Scan /proc/self/maps and hide every UNNAMED EXECUTABLE region from this process's
 * /proc/self/{maps,smaps}, via the KPM's mm-gated maps-hide. Those regions are this process's
 * injected footprint: LSPlant's trampoline pool (rwxp anon, minted per DoHook), the KPM's region
 * clones (r-xp anon) -- and ART's ~1.29MB in-memory-dex code region, which exists only because
 * Vector loads the framework dex in memory, i.e. it is OUR footprint too and an anti-tamper scan
 * would flag it exactly like the pools. All of them close detection surface #2 by being gone.
 *
 * ONE hide-set entry PER REGION, not per page. The KPM's filter matches the entry against the
 * VMA's vm_start (shpte.c maps_hide_vma: `if (g_hide[i].page != vm_start) continue;`), so a
 * single registration hides the whole VMA -- the same thing the pghook hide branch beside it does
 * with a range test. The per-page loop that used to be here cost 315 entries for that one 1.29MB
 * region and so filled the KPM's MAX_HIDE=64 set on its own, leaving the actual pools (the pages
 * that mattered) unhidden: the budget was never the problem, the granularity was.
 *
 * The suspect rule stays deliberately narrow -- executable AND with NO pathname. A NAMED
 * anonymous region (e.g. `[anon:jit-code-cache]`, ART's JIT cache) is normal on any JIT-ing ART
 * runtime and MUST stay visible; widening this rule would hide legitimate mappings.
 *
 * Concurrency: this function must be called with g_lock RELEASED. kpm_hide_region() takes g_lock
 * itself, and g_lock is a plain (non-recursive) mutex -- holding it here would self-deadlock.
 *
 * Safety: nothing here is VA-scoped. Each region-start address is only handed to the KPM's
 * do_hidergn, which records (mm, page) for an equality test in its show_map hook and never
 * dereferences the page -- so this cannot trigger the B.1 "VA unmapped in the issuing context"
 * kernel panic class, even though it runs on the target's own hooking thread.
 *
 * Returns the number of REGIONS the KPM accepted (0 = bridge off / not gated / nothing to hide).
 * Repeat calls are safe and cheap: the KPM's hide-set dedups on (mm, page), so an already-hidden
 * region still answers ok without consuming a new entry. */
int kpm_hide_all_anon_exec(void)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[512];
    int hid = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path);
        if (n < 3) continue;
        int exec = perms[2] == 'x';
        int named = (n >= 4 && path[0]);
        if (!exec || named) continue;
        /* The region's start page IS the hide key: one entry hides the whole VMA. */
        if (kpm_hide_region((void *)(uintptr_t)(lo & ~(PAGE_SZ - 1)))) hid++;
    }
    fclose(f);
    return hid;
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
    /* SSOL regions: unhook each live override so the KPM disarms them (do NOT ssoldisarm --
     * that is global across all processes). */
    for (int i = 0; i < SSOL_MAX_REGIONS; i++) {
        struct srgn *e = &g_srgns[i];
        if (!e->used) continue;
        for (int j = 0; j < SSOL_MAX_OV; j++) {
            if (!e->ov[j].used) continue;
            char cmd[128], out[256];
            snprintf(cmd, sizeof cmd, "ssolunhook %d 0x%lx 0x%lx", g_pid, (unsigned long)e->base,
                     (unsigned long)(e->base + e->ov[j].off));
            bridge_cmd(cmd, out, sizeof out);
        }
        memset(e, 0, sizeof(*e));
    }
    /* WX shadow pages: put the original PTE back for each armed page (wxrelease). Leaving them
     * armed would keep the shadow page behind the VA after this process considers the hook gone. */
    for (int i = 0; i < WX_MAX_PAGES; i++) {
        struct wxent *e = &g_wxents[i];
        if (!e->used) continue;
        if (e->slot >= 0) {
            char cmd[64], out[192];
            snprintf(cmd, sizeof cmd, "wxrelease %d", e->slot);
            bridge_cmd(cmd, out, sizeof out); /* rc/observability already logged at arm time */
        }
        memset(e, 0, sizeof(*e));
    }
    /* B.7.1/B.7.2: the release loop above has already released the shared entry's patch (it is an
     * entry in g_wxents like any other), so the router is unreachable -- drop the state, and the
     * routed table, with it instead of leaving an `armed` flag that no longer describes the
     * process. */
    g_wxr_poll_run = 0;
    g_wxr_prog_n = 0;
    g_wxr_prop_on = 0;
    g_wxr_prop_am = 0;
    g_wxr_prop_repl = 0;
    wxr_republish_locked();
    g_wxr_armed = 0;
    g_wxr_entry = 0;
    g_wxr_router = 0;
    pthread_mutex_unlock(&g_lock);
}
