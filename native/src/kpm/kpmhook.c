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

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "dbi.h"
#include "kpmhook.h"

#define BRIDGE_MAGIC 0x5348505442524447ULL /* "SHPTBRDG" -- matches kpm/shpte.c */
#ifndef __NR_personality
#define __NR_personality 92 /* arm64 asm-generic */
#endif

#define PAGE_SZ 0x1000UL
#define PAGE_INSN 1024              /* instructions in one 4 KiB page */
#define CLONE_CAP 6144             /* 1024 insns can expand ~5x (mirrors pgtool.c) */
#define KPM_MAX_PAGES 24           /* must not exceed the KPM's MAX_PG */
#define KPM_MAX_OV 8               /* must not exceed the KPM's MAX_OV */

struct ov {
    uint64_t off;   /* page-relative byte offset of the hooked entry */
    void *replace;  /* the hooker */
    void *backup;   /* in-clone faithful copy of the target */
};

struct pgent {
    int used;
    uint64_t page;            /* page base of the trapped code page */
    void *clone;              /* whole-page DBI clone (RX mmap) */
    size_t clone_sz;          /* mmap size (page-rounded) */
    uint32_t offmap[PAGE_INSN]; /* orig insn idx -> clone insn idx (read by the KPM) */
    int nmap;
    struct ov ov[KPM_MAX_OV];
    int nov;                  /* live overrides on this page */
};

static struct pgent g_pages[KPM_MAX_PAGES];
static uint32_t g_clonebuf[CLONE_CAP]; /* dbi scratch, reused under g_lock */
static int g_pid = 0;
static int g_inited = 0;      /* 1 = bridge verified live */
static int g_init_failed = 0; /* 1 = probed once and the bridge was off (don't re-probe) */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

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
    if (g_init_failed) return -1; /* probed once, bridge was off -- don't re-clobber personality */
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

static struct pgent *find_page_locked(uint64_t page)
{
    for (int i = 0; i < KPM_MAX_PAGES; i++)
        if (g_pages[i].used && g_pages[i].page == page) return &g_pages[i];
    return 0;
}

/* Build the whole-page DBI clone for `page` (mirrors pgtool.c make_clone). Returns
 * a populated, reusable registry entry, or NULL. */
static struct pgent *make_page_locked(uint64_t page)
{
    struct pgent *e = 0;
    for (int i = 0; i < KPM_MAX_PAGES; i++)
        if (!g_pages[i].used) { e = &g_pages[i]; break; }
    if (!e) return 0; /* registry full */

    /* bound LDR-literal pool reads to +/-8 MiB around the page (mapped segments) */
    int n = dbi_recompile_range(page, (const uint32_t *)(uintptr_t)page, PAGE_INSN, g_clonebuf,
                                CLONE_CAP, e->offmap, PAGE_INSN, (uintptr_t)(page - 0x800000),
                                (uintptr_t)(page + 0x800000));
    if (n < 0) return 0;

    size_t sz = ((size_t)n * 4 + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1);
    void *clone = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) return 0;
    memcpy(clone, g_clonebuf, (size_t)n * 4);
    __builtin___clear_cache((char *)clone, (char *)clone + sz);
    if (mprotect(clone, sz, PROT_READ | PROT_EXEC) != 0) {
        munmap(clone, sz);
        return 0;
    }

    e->page = page;
    e->clone = clone;
    e->clone_sz = sz;
    e->nmap = PAGE_INSN;
    e->nov = 0;
    e->used = 1;
    return e;
}

static void add_ov_locked(struct pgent *e, uint64_t off, void *replace, void *backup)
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

static void remove_ov_locked(struct pgent *e, uint64_t off)
{
    for (int i = 0; i < e->nov; i++)
        if (e->ov[i].off == off) {
            for (int j = i; j < e->nov - 1; j++) e->ov[j] = e->ov[j + 1];
            e->nov--;
            return;
        }
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

    uintptr_t t = (uintptr_t)target;
    uint64_t page = (uint64_t)(t & ~(PAGE_SZ - 1));
    uint64_t off = (uint64_t)(t & (PAGE_SZ - 1));

    struct pgent *e = find_page_locked(page);
    if (!e) e = make_page_locked(page);
    if (!e) goto out;

    backup = (char *)e->clone + (size_t)e->offmap[off / 4] * 4;

    char cmd[192], out[256];
    snprintf(cmd, sizeof cmd, "pghook %d 0x%lx 0x%lx 0x%lx %lu 0x%lx 0x%lx", g_pid,
             (unsigned long)page, (unsigned long)(uintptr_t)e->clone,
             (unsigned long)(uintptr_t)e->offmap, (unsigned long)PAGE_INSN, (unsigned long)off,
             (unsigned long)(uintptr_t)hooker);
    bridge_cmd(cmd, out, sizeof out);
    if (!reply_ok(out)) { backup = 0; goto out; }

    add_ov_locked(e, off, hooker, backup);

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
    uint64_t page = (uint64_t)(f & ~(PAGE_SZ - 1));
    uint64_t off = (uint64_t)(f & (PAGE_SZ - 1));

    char cmd[128], out[256];
    snprintf(cmd, sizeof cmd, "pgunhook %d 0x%lx 0x%lx", g_pid, (unsigned long)page,
             (unsigned long)off);
    bridge_cmd(cmd, out, sizeof out);
    ok = reply_ok(out);
    if (ok) {
        struct pgent *e = find_page_locked(page);
        if (e) remove_ov_locked(e, off); /* keep the clone mapped until shutdown */
    }

out:
    pthread_mutex_unlock(&g_lock);
    return ok;
}

void kpm_hook_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < KPM_MAX_PAGES; i++) {
        if (!g_pages[i].used) continue;
        if (g_pages[i].clone) munmap(g_pages[i].clone, g_pages[i].clone_sz);
        memset(&g_pages[i], 0, sizeof(g_pages[i]));
    }
    pthread_mutex_unlock(&g_lock);
}
