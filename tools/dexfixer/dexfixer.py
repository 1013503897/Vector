#!/usr/bin/env python3
"""dexfixer — reconstruct a loadable .dex from a raw memory-region dump produced by Vector's
direction-1 class-dex finder (persist.kpmhook.unpack.dexfind=1 -> region_<hexstart>_<size>.bin).

Packers like NetEase Yidun load the real classes.dex in-memory (InMemoryDexClassLoader) and then
ZERO/MANGLE the dex header (magic + the leading header fields) once ART has cached begin_/size_ in
its DexFile object. So a header-validating whole-dex scan misses it, but the dex *body* (string
table, type/method ids, class_defs, code items, map_list) stays intact in cleartext — that is what
the finder dumps the containing region for.

This tool relocates the real dex inside the region by the header invariants that survive
(header_size==0x70 at hdr+0x24, endian_tag==0x12345678 at hdr+0x28), reconstructs the 8-byte magic
(dex\n0NN\0 inferred from the version bytes that follow), recomputes checksum (adler32) + signature
(sha1), and writes a clean .dex. The dex base may sit a few bytes *before* the page-aligned region
start (the leading magic bytes then fall outside the dump) — those bytes are part of the magic we
overwrite anyway, so the recovery is exact.

Usage:
    python dexfixer.py <region_*.bin> [out_dir]
    python dexfixer.py <dir-of-region-bins> [out_dir]
"""
import os
import sys
import struct
import zlib
import hashlib

ENDIAN_TAG = 0x12345678
HEADER_SIZE = 0x70


def find_dex_headers(buf):
    """Yield region offsets P where a dex header sits (header_size & endian_tag intact),
    even if the magic is mangled. dex base = P - 0x24."""
    n = len(buf)
    i = 0
    out = []
    while i < n - 0x2c:
        # header_size (u32) at hdr+0x24, endian_tag (u32) at hdr+0x28
        if buf[i:i + 4] == b'\x70\x00\x00\x00' and buf[i + 4:i + 8] == b'\x78\x56\x34\x12':
            base = i - 0x24                     # start of the dex header (may be < 0)
            # file_size is at hdr+0x20 == base+0x20 == region (i - 4)
            fs_off = i - 4
            if fs_off >= 0:
                file_size = struct.unpack_from('<I', buf, fs_off)[0]
                if 0x70 < file_size <= n - base + 8:
                    out.append((base, file_size))
        i += 4
    return out


def reconstruct(buf, base, file_size):
    """Return a clean dex bytearray for the dex at [base, base+file_size) inside `buf`.
    base may be negative (leading magic bytes precede the region) — those are reconstructed."""
    dex = bytearray(file_size)
    # copy the bytes we actually have: dex[i] = buf[base + i] for base+i in [0, len(buf))
    lo = max(0, -base)                          # first dex index whose source byte exists
    src_start = base + lo
    src_end = min(len(buf), base + file_size)
    ncopy = src_end - src_start
    dex[lo:lo + ncopy] = buf[src_start:src_start + ncopy]

    # magic: "dex\n0NN\0". The version digits live at dex[4:7]; if missing, default to 035.
    ver = bytes(dex[4:7])
    if not (ver.isdigit()):
        ver = b'035'
        dex[4:7] = ver
    dex[0:4] = b'dex\n'
    dex[7] = 0x00

    # signature = sha1(dex[32:]) ; checksum = adler32(dex[12:])
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    struct.pack_into('<I', dex, 8, zlib.adler32(bytes(dex[12:])) & 0xffffffff)
    return dex


def validate(dex):
    """Cheap structural check: walk every string_id once. Returns (ok_count, total, class_defs)."""
    if dex[0:4] != b'dex\n':
        return (0, 0, 0)
    sids_sz = struct.unpack_from('<I', dex, 0x38)[0]
    sids_off = struct.unpack_from('<I', dex, 0x3c)[0]
    cdef_sz = struct.unpack_from('<I', dex, 0x60)[0]
    ok = 0
    for i in range(sids_sz):
        try:
            so = struct.unpack_from('<I', dex, sids_off + i * 4)[0]
            if so < len(dex):
                ok += 1
        except struct.error:
            break
    return (ok, sids_sz, cdef_sz)


def process(path, out_dir):
    buf = open(path, 'rb').read()
    hdrs = find_dex_headers(buf)
    if not hdrs:
        print(f"  {os.path.basename(path)}: no dex header invariants found")
        return 0
    made = 0
    for idx, (base, file_size) in enumerate(hdrs):
        dex = reconstruct(buf, base, file_size)
        ok, total, classes = validate(dex)
        tag = "OK" if ok == total and total else "PARTIAL"
        stem = os.path.splitext(os.path.basename(path))[0]
        out = os.path.join(out_dir, f"{stem}_fixed{'' if idx == 0 else '_' + str(idx)}.dex")
        open(out, 'wb').write(dex)
        print(f"  {os.path.basename(path)}: base={base:#x} file_size={file_size} "
              f"string_ids={ok}/{total} class_defs={classes} [{tag}] -> {os.path.basename(out)}")
        made += 1
    return made


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    src = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else (src if os.path.isdir(src) else os.path.dirname(src) or '.')
    os.makedirs(out_dir, exist_ok=True)
    if os.path.isdir(src):
        files = [os.path.join(src, f) for f in sorted(os.listdir(src))
                 if f.startswith('region_') and f.endswith('.bin')]
    else:
        files = [src]
    total = 0
    for f in files:
        total += process(f, out_dir)
    print(f"done: {total} dex file(s) written to {out_dir}")


if __name__ == '__main__':
    main()
