// dex_layout.cpp — CodeItem length parser (see dex_layout.h). INERT until VECTOR_UNPACK_ENABLED.
//
// Pure dex-format; no ART. Parses the standard CodeItem trailer (try_items + the
// uleb128-encoded catch-handler list) to recover the exact byte length, so the per-method
// capture (P0-design) copies precisely [code_item, code_item + len).

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/dex_layout.h"

namespace vector::native::unpack::dex {

namespace {

// Read an unsigned LEB128, advancing *p. No bounds arg: caller bounds via the dex image.
uint32_t ReadUleb128(const uint8_t **p) {
    const uint8_t *ptr = *p;
    uint32_t result = *ptr & 0x7f;
    if (*ptr++ & 0x80) {
        result |= (uint32_t)(*ptr & 0x7f) << 7;
        if (*ptr++ & 0x80) {
            result |= (uint32_t)(*ptr & 0x7f) << 14;
            if (*ptr++ & 0x80) {
                result |= (uint32_t)(*ptr & 0x7f) << 21;
                if (*ptr++ & 0x80) {
                    result |= (uint32_t)(*ptr & 0x7f) << 28;
                    ptr++;
                }
            }
        }
    }
    *p = ptr;
    return result;
}

// Read a signed LEB128 (used by encoded_catch_handler.size sign).
int32_t ReadSleb128(const uint8_t **p) {
    const uint8_t *ptr = *p;
    int32_t result = *ptr & 0x7f;
    int shift = 7;
    if (*ptr++ & 0x80) {
        for (; shift < 32; shift += 7) {
            uint8_t b = *ptr++;
            result |= (int32_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) {
                if (shift + 7 < 32 && (b & 0x40)) result |= -(1 << (shift + 7));
                break;
            }
        }
    }
    *p = ptr;
    return result;
}

}  // namespace

size_t CodeItemLength(const uint8_t *ci) {
    if (!ci) return 0;
    // Fixed 16-byte standard CodeItem header.
    uint16_t tries_size = *reinterpret_cast<const uint16_t *>(ci + 6);
    uint32_t insns_size = *reinterpret_cast<const uint32_t *>(ci + 12);
    // Sanity caps: a real standard CodeItem never has these magnitudes. They bound the parse so a
    // NON-standard input (a CompactDex CodeItem, whose +6/+12 fields mean something else, or random
    // memory) returns 0 fast instead of running away in the handler loop below.
    if (insns_size > (1u << 20)) return 0;        // > 1M code units
    if (tries_size > 8192) return 0;

    const uint8_t *p = ci + 16;            // start of insns[]
    p += (size_t)insns_size * 2;           // u2 insns[insns_size]
    if (tries_size == 0) {
        return (size_t)(p - ci);           // no tries/handlers
    }
    // Optional u2 padding to 4-byte-align the try_item array.
    if (insns_size & 1) p += 2;
    // try_item[tries_size], 8 bytes each (u4 start_addr; u2 insn_count; u2 handler_off).
    p += (size_t)tries_size * 8;

    // encoded_catch_handler_list: uleb128 size, then `size` encoded_catch_handler entries.
    uint32_t handler_count = ReadUleb128(&p);
    if (handler_count > 65536) return 0;          // cap (garbage input)
    for (uint32_t i = 0; i < handler_count; i++) {
        int32_t size = ReadSleb128(&p);           // signed: <0 means a catch-all follows
        uint32_t pairs = (size < 0) ? (uint32_t)(-size) : (uint32_t)size;
        if (pairs > 65536) return 0;              // cap
        for (uint32_t j = 0; j < pairs; j++) {
            ReadUleb128(&p);                      // type_idx
            ReadUleb128(&p);                      // address
        }
        if (size <= 0) ReadUleb128(&p);           // catch_all_addr
    }
    return (size_t)(p - ci);
}

}  // namespace vector::native::unpack::dex

#endif  // VECTOR_UNPACK_ENABLED
