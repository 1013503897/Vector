#pragma once

// codeitem_sink — buffers captured CodeItems + whole-dex images and flushes them to an
// app-uid-writable path. The offline reassembler (tools/dexfixer/, NOT in this repo)
// then splices the captured CodeItems back into each whole-dex image. Design §5.

#include <cstddef>
#include <cstdint>

namespace vector::native::unpack {

// One captured method body. `bytes`/`len` describe the CodeItem as it sits in memory
// AFTER the shell restored it (the whole point of capturing at the choke point).
struct CaptureRecord {
    uint32_t dex_id;          // index returned by RegisterDex()
    uint32_t method_idx;      // ArtMethod::GetDexMethodIndex()
    const void *code_item;    // pointer into the (restored) dex memory
    uint32_t len;             // CodeItem length in bytes (header + insns + tries/handlers)
};

class CodeItemSink {
public:
    // out_dir must be writable by the app uid (e.g. /data/data/<pkg>/unpack). Idempotent.
    bool Init(const char *out_dir);

    // Record a DexFile's whole-memory image once (dumped immediately). Returns a stable
    // dex_id used by Capture(); returns the same id for the same (begin) seen again.
    uint32_t RegisterDex(const void *begin, size_t size);

    // Record one restored CodeItem. Cheap + lock-guarded; safe from the hot choke cb.
    void Capture(const CaptureRecord &rec);

    // Persist everything (whole-dex images + the CodeItem index) for offline reassembly.
    void Flush();

    size_t dex_count() const { return dex_count_; }
    size_t capture_count() const { return capture_count_; }

private:
    // TODO(P0): backing store. Keep the hot path allocation-free — append fixed-size
    // index records to a preallocated arena + dump CodeItem bytes to a per-dex blob;
    // dedup by (dex_id, method_idx). Whole-dex images dumped in RegisterDex.
    size_t dex_count_ = 0;
    size_t capture_count_ = 0;
};

}  // namespace vector::native::unpack
