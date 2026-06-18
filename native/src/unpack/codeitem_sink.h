#pragma once

// codeitem_sink — buffers captured DEX images + CodeItems and flushes them to a writable
// path. The offline reassembler (tools/dexfixer/, NOT in this repo) then splices the
// captured CodeItems back into each whole-dex image. Design §5.
//
// P0-simple (whole-dex shells): ObserveCodeItem(ci) is called from the GetCodeItem choke
// for every method whose bytecode ART touches. From the inner CodeItem pointer the sink
// recovers the containing dex image ([base, base+file_size)) via a /proc/self/maps-bounded
// backward scan and dumps it ONCE (range-deduped). No ART struct offsets.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace vector::native::unpack {

// One captured method body (P0-design per-method path; unused by P0-simple).
struct CaptureRecord {
    uint32_t dex_id;
    uint32_t method_idx;
    const void *code_item;
    uint32_t len;
};

class CodeItemSink {
public:
    // out_dir must be writable by the app uid (e.g. <app_data_dir>/unpack). Idempotent.
    bool Init(const char *out_dir);

    // P0-simple (Tier-A) whole-dex dump: walk /proc/self/maps and dump every app dex image
    // found in a readable, non-framework region (magic + header validated). No ART internals,
    // no choke hook -> immune to libart inlining the CodeItem accessors. Run once after the
    // shell has decrypted its dex(es) into memory. Range-deduped.
    void ScanProcessForDexes();

    // Choke-hook entry (P0-design / higher tiers): observe a (restored) CodeItem pointer. On
    // the first sighting of its containing dex, recover + dump the whole image. NOTE: hooking
    // ArtMethod::GetCodeItem catches few calls (libart inlines it at most call sites) -> this
    // is for active/per-method tiers, not the P0-simple whole-dex path. Concurrency-safe.
    void ObserveCodeItem(const void *code_item);

    // Direction-1 increment-1 (extraction / header-mangled in-memory dex): given a pointer
    // KNOWN to lie inside a live dex (e.g. mirror::Class::GetClassDef() -> dex::ClassDef*),
    // dump the WHOLE containing /proc/self/maps region WITHOUT validating a dex header. This
    // recovers dexes that ScanProcessForDexes misses because the packer (NetEase Yidun) mangles
    // the in-memory header so IsDexHeader rejects the region. Region-deduped; fault-guarded.
    // Writes <dir>/region_<hexstart>_<size>.bin (raw) and, if a valid dex header is also found
    // at the region start, a clean <dir>/dump_*.dex too. Concurrency-safe.
    void DumpRegionContaining(const void *inner_ptr);

    // Batch form of DumpRegionContaining for the class enumerator (tens of thousands of
    // ClassDef pointers, most in framework dexes): snapshots /proc/self/maps ONCE, resolves
    // every pointer to its region by binary search, then dumps each DISTINCT app region a
    // single time. Avoids the O(N) re-parse of maps that DumpRegionContaining would incur per
    // pointer. `ptrs` are inner pointers (e.g. dex::ClassDef*). Region-deduped; fault-guarded.
    void DumpRegionsForPointers(const void *const *ptrs, size_t n);

    // P0-design entries (per-method CodeItem capture). Kept for the extraction-shell path.
    uint32_t RegisterDex(const void *begin, size_t size);
    void Capture(const CaptureRecord &rec);

    // increment-2b (side-cache extraction shells, e.g. dpt-shell): one restored CodeItem per
    // method, already copied to a SAFE caller-owned buffer. The finder copies the CodeItem bytes
    // the instant GetCodeItem returns (the restored CodeItem lives in a transient side structure
    // that the shell recycles, so the pointer goes stale by the time the worker would read it).
    // `classdef` locates the owning dex (its /proc/self/maps region == the dumped region);
    // `method_idx` is the dex method index; `bytes`/`len` are the safe CodeItem copy. The sink just
    // resolves classdef -> region and writes <dir>/captures.txt lines
    // "<region_start_hex> <method_idx> <codeitem_hex>" for the offline splicer.
    struct MethodCapture {
        const void *classdef;
        uint32_t method_idx;
        const uint8_t *bytes;
        uint32_t len;
    };
    size_t DumpMethodCaptures(const MethodCapture *caps, size_t n);

    // Persist everything for offline reassembly.
    void Flush();

    size_t dex_count() const { return dex_count_; }
    size_t capture_count() const { return capture_count_; }

private:
    struct DexRange {
        const uint8_t *base;
        const uint8_t *end;   // base + file_size
        uint32_t id;
    };
    // Returns the id if `inner` lies within an already-dumped dex, else -1. Caller holds lock_.
    long FindRangeLocked(const uint8_t *inner) const;
    // Dump [base, base+size) to <dir>/dump_<checksum>_<size>.dex. Caller holds lock_.
    void DumpDexLocked(const uint8_t *base, size_t size);
    // On-device dexfixer: reconstruct valid .dex(es) from a SAFE region copy by header invariants
    // (rebuild magic + adler32 + sha1) -> <dir>/region_<start>_<size>_fixed.dex. Caller holds lock_.
    void ReconstructDexesFromRegion(const uint8_t *region, size_t size, uintptr_t region_start);

    std::mutex lock_;
    std::vector<DexRange> ranges_;
    char dir_[256] = {0};
    bool inited_ = false;
    size_t dex_count_ = 0;
    size_t capture_count_ = 0;
};

}  // namespace vector::native::unpack
