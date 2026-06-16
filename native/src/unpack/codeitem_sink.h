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

    // P0-design entries (per-method CodeItem capture). Kept for the extraction-shell path.
    uint32_t RegisterDex(const void *begin, size_t size);
    void Capture(const CaptureRecord &rec);

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

    std::mutex lock_;
    std::vector<DexRange> ranges_;
    char dir_[256] = {0};
    bool inited_ = false;
    size_t dex_count_ = 0;
    size_t capture_count_ = 0;
};

}  // namespace vector::native::unpack
