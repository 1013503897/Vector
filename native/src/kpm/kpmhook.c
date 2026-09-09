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
//
// -------------------------------------------------------------------------------------------
// VENDORED from stealth-core @ 2a148bca2e4ef00ba1cdf5eb58122ec87c51b406 (upstream date 2026-09-01).
// This is NOT a byte-for-byte copy of stealth-core lib/kpmhook.c -- it is a documented superset.
// Vector-side deltas (see native/src/kpm/SYNC.md for the authoritative, line-referenced list):
//   * process gating: INJECTED_PACKAGE_NAME / INJECTED_PACKAGE_UID compile gates + the runtime
//     kpm_hook_set_process_name() name channel (the app name is unknown at hook time in Vector).
//   * inlined SSOL *client* glue (kpm_ssol_hooker/kpm_ssol_unhooker + srgn/sov tables) that
//     drives the KPM `ssolhook`/`ssolunhook` bridge commands. NOTE: this is the userspace
//     bridge client, a DIFFERENT layer from stealth-core's lib/ssol.c (which is the offline SSOL
//     *simulator* that runs kernel-side); there is no upstream client file to converge toward.
//   * kpm_hide_region() maps-hide client, and the SSOL teardown loop in kpm_hook_shutdown().
//   * the bridge `version` handshake client (verify_bridge_version_locked; bridge-protocol.md).
// Keep the shared clone-path logic (make_rgn/find_rgn/emit/offmap) in lock-step with upstream:
// when syncing an upstream fix, apply it here too and record it in SYNC.md.
// -------------------------------------------------------------------------------------------

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
#define CLIENT_BRIDGE_PROTO 1      /* bridge wire protocol this client speaks (see docs/bridge-protocol.md) */

/* #12: bridge `version` handshake -- ADVISORY-ONLY (defined after the SSOL caps below so it can
 * bound-check them for the diagnostic). Forward-declared here for ensure_init_locked(). It ONLY
 * logs; it MUST NOT change any hook/fallback decision -- falling back to Dobby is fatal on
 * anti-tamper targets like GCash (SIGKILL), so a missing/mismatched `version` must never disable
 * the KPM backend. See its definition for the full rationale. */
static void advise_bridge_version_locked(void);

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
/* #6/P6: the census recompiles ONE function of up to fn_len_insns()'s 2048-insn cap; with the
 * 128-bit SIMD LDR-literal form now emitting 6 clone words per insn (dbi.c insn_size), the clone
 * can reach ~6x -> ~12288 words. CLONE_CAP (6144) was too small: dbi_recompile returned
 * DBI_ERR_RANGE and the census silently logged dbi_rc=-1. Size the clone scratch for the real
 * worst case so the dry-run actually measures the span it exists to measure. */
#define CENSUS_CLONE_CAP 16384
static uint32_t g_clonebuf[CENSUS_CLONE_CAP]; /* characterize dbi clone scratch, reused under g_lock */
static uint32_t g_scratch_omap[CLONE_CAP]; /* characterize dbi offmap scratch (<= src insns), under g_lock */
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

    /* UID fallback: the injected host is UID-specialized at hook time even when no name was
     * passed (e.g. 2000 = the shell-UID parasitic LSPosed manager host). KPM_TARGET_UID is
     * ALWAYS defined (INJECTED_PACKAGE_UID from the build, or the 2000 fallback above), so this
     * is an unconditional check -- no `#ifdef` needed (it was always true). */
    if ((int)getuid() == KPM_TARGET_UID) return 1;
#ifdef INJECTED_PACKAGE_NAME
    /* the build's injection target (compile-time, SELinux-proof) */
    if (strcmp(name, KPM_STR(INJECTED_PACKAGE_NAME)) == 0) return 1;
#endif
    /* KPM_RV0_TARGET / KPM_TARGET are TEST-BUILD-ONLY compile targets (stealth-core's standalone
     * harness / RV-0 census build); they are NOT defined in Vector's product build, so the two
     * branches below are dead there. Kept #ifdef-isolated for parity with stealth-core lib/kpmhook.c. */
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
    int rc = dbi_recompile(t, (const uint32_t *)t, len + 4, g_clonebuf, CENSUS_CLONE_CAP,
                           g_scratch_omap, CLONE_CAP);
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "census target=%p page=0x%lx off=0x%lx len=%d end=0x%lx pages=%d dbi_rc=%d%s%s",
                        target, (unsigned long)page, (unsigned long)off, len, (unsigned long)end,
                        pages, rc, pages > 1 ? " SPANS" : "",
                        rc == DBI_ERR_RANGE ? " (clone > CENSUS_CLONE_CAP: function too large, span not fully measured)" : "");
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
    /* #12: ADVISORY-ONLY bridge `version` handshake, run once here (this body runs once -- gated by
     * g_inited/g_init_failed -- so the query never repeats per-hook). It ONLY emits diagnostics; it
     * deliberately does NOT gate init. Rationale: probe already proved the KPM + bridge are live, and
     * on an anti-tamper target (GCash) falling back to Dobby = SIGKILL, so a missing/mismatched
     * `version` (e.g. an in-service KPM predating the command) must NOT disable the KPM backend. */
    advise_bridge_version_locked();
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
 * addr is not in a readable mapping. Two uses, both against hardened/packed libs (some
 * commercial packers) that split their .text with non-readable --xp/---p sub-ranges:
 *   1. cap region expansion at [.,end) so dbi_recompile's [base,end) read stays readable;
 *   2. bound dbi's LDR-literal-pool reads to [start,end) so a bytecode word MISDECODED as
 *      an LDR-literal (obfuscated VM) resolving OUTSIDE the readable extent is SKIPPED, not
 *      read -- that out-of-extent read (e.g. base-486KB, below the packed lib) SIGSEGVs otherwise.
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
        if (cand && !va_range_mapped(cand, sz)) return cand;
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
     * clone, and packed libs split .text with non-readable sub-ranges -> a read
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

/* #P5/#P7: PRECONDITION -- both setters below MUST be called before the first hook (i.e. before
 * any other thread enters kpm_inline_hooker/kpm_ssol_hooker). Under that contract the writes race
 * with nothing, so they are intentionally lockless (matches stealth-core lib/kpmhook.c) even though
 * g_force_enable/g_ghost are read under g_lock on the hook path. Do NOT call them mid-run.
 * kpm_hook_force_enable is vendored-for-completeness: it has NO Vector caller (Vector relies on the
 * process gate + Dobby fallback); it exists only for stealth-core's standalone tools/kpmhooktool. */
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
        /* #P1: if this region was FRESHLY made for this hook (no live overrides yet), the KPM
         * never armed it -- release the clone mmap + offmap and free the registry slot so a
         * rejected hook doesn't leak a region (clone VMA + heap offmap + a KPM_MAX_REGIONS slot).
         * Mirrors the SSOL "freshly-made-but-unused" release in kpm_ssol_hooker and make_rgn's own
         * error unwinds. A REUSED region (nov>0) still backs other live hooks -> keep it. `clone`
         * is an mmap in BOTH legacy and ghost mode, so munmap is always correct here. */
        if (e->nov == 0) {
            munmap(e->clone, e->clone_sz);
            free(e->offmap);
            e->used = 0;
        }
        backup = 0;
        goto out;
    }

    add_ov_locked(e, roff, hooker, backup);

out:
    pthread_mutex_unlock(&g_lock);
    return backup;
}

/* #P2: TRI-STATE return (was a plain 0/1 "ok" that conflated two very different zeros).
 *   -1 = NOT a KPM hook (bridge down, or this addr was never region-hooked) -> caller should
 *        DobbyDestroy it.
 *    0 = it IS our KPM hook but the bridge teardown FAILED -> the KPM trap may still be armed.
 *        The caller must NOT then DobbyDestroy (this addr was never Dobby-hooked); it should
 *        surface the failure. We also WARN here so the reject is never silent.
 *    1 = torn down cleanly.
 * UnhookInline (native_api.h) branches on all three. */
int kpm_inline_unhooker(void *func)
{
    int rc = -1; /* default: not ours -> caller falls back to Dobby */
    pthread_mutex_lock(&g_lock);
    if (!g_inited) goto out; /* bridge never armed -> no KPM hooks exist -> treat as not-ours */

    uintptr_t f = (uintptr_t)func;
    struct rgn *e = find_rgn_locked(f);
    if (!e) goto out; /* not a KPM-hooked function -> -1 (caller uses Dobby) */
    uint64_t roff = f - e->base; /* region-relative */

    char cmd[128], out[256];
    snprintf(cmd, sizeof cmd, "pgunhook %d 0x%lx 0x%lx", g_pid, (unsigned long)e->base,
             (unsigned long)roff);
    bridge_cmd(cmd, out, sizeof out);
    if (reply_ok(out)) {
        remove_ov_locked(e, roff); /* keep the clone/offmap until shutdown */
        rc = 1;
    } else {
        __android_log_print(ANDROID_LOG_WARN, KPM_LOG_TAG,
                            "pgunhook FAILED (KPM trap may still be armed): cmd=[%s] reply=[%s]",
                            cmd, out);
        rc = 0; /* ours, but teardown failed -- caller must NOT DobbyDestroy */
    }

out:
    pthread_mutex_unlock(&g_lock);
    return rc;
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

/* ===================== #12: bridge `version` handshake client (ADVISORY-ONLY) =====================
 * Contract: stealth-core/docs/bridge-protocol.md. At init (once) we send the literal command
 * "version" and parse the reply
 *     ok: shptbridge proto=1 MAX_RGN=64 MAX_PG=16 MAX_OV=8 MAX_GHOST_PG=512 MAX_SSOL_RGN=16 ...
 *
 * ⚠️ CRITICAL DESIGN NOTE -- the handshake is ADVISORY-ONLY: it emits diagnostics and NOTHING else.
 * It must NEVER disable the KPM backend, set g_init_failed, or otherwise change a hook/fallback
 * decision. Reason: on an anti-tamper target (e.g. GCash), falling back to Dobby is FATAL -- a Dobby
 * inline patch trips the app's self-check and the process is SIGKILL'd. A new Vector running against
 * an in-service KPM that predates the `version` command must keep working exactly as before. probe
 * already proved the bridge is live; `version` only tells a human whether the two sides' ABI match.
 *
 *   - no `ok: shptbridge` prefix (old KPM doesn't know the command) -> INFO, keep using KPM (compat).
 *   - proto mismatch / a client cap exceeds the KPM's -> prominent ERROR for ABI-drift triage, but
 *     STILL keep using KPM (do not touch the hook path). */

/* Parse a decimal `key=value` token (matched at a word boundary). Returns 1 + *out on success. */
static int bridge_kv(const char *s, const char *key, long *out)
{
    size_t klen = strlen(key);
    for (const char *p = s; (p = strstr(p, key)); p += klen) {
        if ((p == s || p[-1] == ' ') && p[klen] == '=') { /* word-boundary + '=' */
            *out = strtol(p + klen + 1, NULL, 10);
            return 1;
        }
    }
    return 0;
}

/* ADVISORY-ONLY: logs an ABI diagnostic and returns void. Never gates init. Called once from
 * ensure_init_locked() under g_lock (naturally cached: that body runs once). */
static void advise_bridge_version_locked(void)
{
    char out[256];
    bridge_cmd("version", out, sizeof out);
    static const char PFX[] = "ok: shptbridge";
    if (strncmp(out, PFX, sizeof(PFX) - 1) != 0) {
        /* Old KPM without the `version` command (or a stray reply). This is NOT an error: the proven
         * clone/SSOL path predates `version`. Keep using the KPM. */
        __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                            "bridge `version` absent/unrecognized (reply=[%s]); assuming a pre-version "
                            "KPM -- continuing in compat mode, KPM backend stays ENABLED.", out);
        return;
    }
    long proto = 0;
    if (!bridge_kv(out, "proto", &proto) || proto != CLIENT_BRIDGE_PROTO) {
        __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                            "bridge proto MISMATCH (client=%d, reply=[%s]) -- ABI drift, please "
                            "investigate. KPM backend left ENABLED (fallback would be fatal on "
                            "protected targets).", CLIENT_BRIDGE_PROTO, out);
        return;
    }
    /* Diagnostic capacity check: each client compile-time cap should be <= the KPM's reported value. */
    long max_rgn = 0, max_pg = 0, max_ov = 0, max_ssol_rgn = 0, max_ssol_ov = 0;
    bridge_kv(out, "MAX_RGN", &max_rgn);
    bridge_kv(out, "MAX_PG", &max_pg);
    bridge_kv(out, "MAX_OV", &max_ov);
    bridge_kv(out, "MAX_SSOL_RGN", &max_ssol_rgn);
    bridge_kv(out, "MAX_SSOL_OV", &max_ssol_ov);
    if (MAX_RGN_PAGES > max_rgn || KPM_MAX_REGIONS > max_pg || KPM_MAX_OV > max_ov ||
        SSOL_MAX_REGIONS > max_ssol_rgn || SSOL_MAX_OV > max_ssol_ov) {
        __android_log_print(ANDROID_LOG_ERROR, KPM_LOG_TAG,
                            "bridge capacity SMALLER than this client expects "
                            "(need RGN=%d PG=%d OV=%d SSOL_RGN=%d SSOL_OV=%d; KPM reply=[%s]) -- ABI "
                            "drift, please investigate. KPM backend left ENABLED (fallback would be "
                            "fatal on protected targets).",
                            MAX_RGN_PAGES, KPM_MAX_REGIONS, KPM_MAX_OV, SSOL_MAX_REGIONS,
                            SSOL_MAX_OV, out);
        return;
    }
    __android_log_print(ANDROID_LOG_INFO, KPM_LOG_TAG,
                        "bridge `version` OK: proto=%ld matches, capacities sufficient.", proto);
}

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

/* #P7: vendored-for-completeness -- NO Vector caller. Vector's injected agent lives for the whole
 * process lifetime and lets the KPM auto-disarm on process exit, so it never calls shutdown; this
 * exists for stealth-core's standalone tools/kpmhooktool (which explicitly tears down). Kept so the
 * two vendored copies stay in sync. */
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
    pthread_mutex_unlock(&g_lock);
}
