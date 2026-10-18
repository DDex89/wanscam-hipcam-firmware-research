#!/usr/bin/env python3
"""Read-only offline inspection of Wanscam backup.cgi .bin trailers.

Usage: py wanscam_backup_trailer_inspect.py wanscam_backup.bin [wanscam_backup_2.bin ...]
Does not extract private configs, print plaintext credentials, or contact camera.
"""
import argparse
import base64
import hashlib
from pathlib import Path
import struct
import zlib


def inspect(path: Path):
    compressed = path.read_bytes()
    z = zlib.decompressobj(wbits=31)
    tar = z.decompress(compressed) + z.flush()
    trailer = z.unused_data
    print(f'FILE: {path.name}')
    print(f'  file_size={len(compressed)} gzip_size={len(compressed)-len(trailer)} tar_size={len(tar)} trailer_size={len(trailer)}')
    print(f'  tar_SHA256={hashlib.sha256(tar).hexdigest()}')
    if len(trailer) != 128:
        print('  WARNING: unexpected trailer length')
        return None
    encoded_length = struct.unpack_from('<I', trailer)[0]
    if encoded_length != 64:
        print(f'  WARNING: unexpected base64 length = {encoded_length}')
        return None
    block = base64.b64decode(trailer[4:68], validate=True)
    if len(block) != 48:
        print('  WARNING: decoded header not 48 bytes')
        return None
    file_type, magic = struct.unpack_from('<II', block)
    print(f'  fixed_trailer_header: encoded_length={encoded_length}, decoded_length={len(block)}, type=0x{file_type:08x}, magic=0x{magic:08x}')
    print(f'  60-byte random_area_SHA256={hashlib.sha256(trailer[68:]).hexdigest()}')
    print('  WARNING: these checks characterize the file; they do not prove restore compatibility or verify authenticity.')
    return tar, block, trailer[68:]


def main():
    ap = argparse.ArgumentParser(description='Inspect Wanscam backup.cgi 128-byte trailer offline')
    ap.add_argument('backup', nargs='+', type=Path)
    args = ap.parse_args()
    results = []
    for f in args.backup:
        try:
            res = inspect(f)
            if res:
                results.append((f.name, res))
        except Exception as e:
            print(f'ERROR {f}: {e}')
    if len(results) >= 2:
        _, (tar0, hdr0, rnd0) = results[0]
        print('\nCOMPARISON AGAINST:', results[0][0])
        for name, (tar, hdr, rnd) in results[1:]:
            print(f'  {name}: TAR_IDENTICAL={tar==tar0}, HEADER_IDENTICAL={hdr==hdr0}, RANDOM_AREA_IDENTICAL={rnd==rnd0}')


if __name__ == '__main__':
    main()