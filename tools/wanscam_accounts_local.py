#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local, read-only Wanscam Linux account extractor and candidate verifier.

Accepts either the owner's 16 MiB MTD image or previously extracted rootfs tar.gz.
No network calls, no external modules, and no writes to the source image.

Examples (Windows PowerShell):
    py .\\wanscam_accounts_local.py .\\wanscam_full_flash_16MiB.bin
    py .\\wanscam_accounts_local.py .\\wanscam_full_flash_16MiB.bin --wordlist .\\wanscam_passwords.txt
    py .\\wanscam_accounts_local.py .\\wanscam_extracted_rootfs.tar.gz --prompt
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import struct
import tarfile
import zlib

TARGET_NAMES = ('etc/passwd', 'etc/shadow')
CRYPT_B64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def jffs_crc(data: bytes) -> int:
    # JFFS2 CRC32 starts from 0xffffffff and is xor-finalized.
    return zlib.crc32(data, 0xffffffff) ^ 0xffffffff


def read_from_flash(path: Path) -> dict[str, bytes]:
    raw = path.read_bytes()
    if len(raw) == 16 * 1024 * 1024:
        blob = memoryview(raw)[0x220000:]
    elif raw[:2] == b'\x85\x19':
        blob = memoryview(raw)
    else:
        raise ValueError('Expected a 16 MiB Wanscam flash image or JFFS2 partition')

    dirents: dict[tuple[int, bytes], list[tuple[int, int, int]]] = {}
    files: dict[int, list[tuple[int, int, int, int, int, bytes]]] = {}
    # Scan only four-byte aligned node starts, validate headers and payload CRCs.
    for pos in range(0, len(blob)-68, 4):
        if blob[pos] != 0x85 or blob[pos+1] != 0x19:
            continue
        _, node_type, node_len, hcrc = struct.unpack_from('<HHII', blob, pos)
        if node_len < 12 or node_len > len(blob)-pos:
            continue
        if jffs_crc(blob[pos:pos+8]) != hcrc:
            continue
        if node_type == 0xE001 and node_len >= 40:
            parent, ver, ino, _t, nlen, ftype, _u, node_crc, name_crc = struct.unpack_from('<IIIIBBHII', blob, pos+12)
            name = bytes(blob[pos+40:pos+40+nlen])
            if len(name) != nlen or jffs_crc(name) != name_crc or jffs_crc(blob[pos:pos+32]) != node_crc:
                continue
            dirents.setdefault((parent, name), []).append((ver, pos, ino))
        elif node_type == 0xE002 and node_len >= 68:
            (ino, ver, mode, uid, gid, isize, atime, mtime, ctime, offset, csize, dsize,
             compr, usercompr, flags, data_crc, node_crc) = struct.unpack_from('<IIIHHIIIIIIIBBHII', blob, pos+12)
            if csize > node_len - 68 or csize > 1048576:
                continue
            content = bytes(blob[pos+68:pos+68+csize])
            if jffs_crc(content) != data_crc or jffs_crc(blob[pos:pos+60]) != node_crc:
                continue
            files.setdefault(ino, []).append((ver, pos, isize, offset, compr, content, dsize))

    # Traverse from JFFS2 inode 1 (/). Only /etc/passwd and /etc/shadow are needed.
    def child(parent: int, name: bytes) -> int:
        entries = dirents.get((parent, name), [])
        return max(entries, default=(0, 0, 0))[2]

    etc = child(1, b'etc')
    if not etc:
        raise ValueError('Cannot locate /etc directory in JFFS2')
    result = {}
    for target in TARGET_NAMES:
        inode_num = child(etc, target.rsplit('/', 1)[-1].encode())
        if not inode_num or inode_num not in files:
            raise ValueError(f'Cannot locate {target} inode in JFFS2')
        revisions = sorted(files[inode_num], key=lambda x: (x[0], x[1]))
        data_size = revisions[-1][2]
        if data_size > 16384:
            raise ValueError(f'Unexpected size for {target}')
        out = bytearray(data_size)
        for ver, node_pos, isize, offset, compression, data, dsize in revisions:
            if not dsize:
                continue
            if compression in (0, 4):
                chunk = data
            elif compression == 1:
                chunk = bytes(dsize)
            elif compression == 6:
                try:
                    chunk = zlib.decompress(data)
                except zlib.error:
                    chunk = zlib.decompress(data, -15)
            else:
                raise ValueError(f'Unsupported compression={compression} in {target}')
            if len(chunk) != dsize:
                raise ValueError(f'Bad fragment size in {target}')
            if offset < data_size:
                out[offset:min(offset+dsize, data_size)] = chunk[:data_size-offset]
        result[target] = bytes(out)
    return result


def read_from_tar(path: Path) -> dict[str, bytes]:
    out = {}
    with tarfile.open(path, 'r:*') as tf:
        for member in tf:
            if not member.isfile():
                continue
            normalized = member.name.lstrip('./')
            for target in TARGET_NAMES:
                if normalized == target or normalized.endswith('/'+target):
                    stream = tf.extractfile(member)
                    if stream:
                        out[target] = stream.read(16385)
    if any(key not in out for key in TARGET_NAMES):
        raise ValueError('The archive must contain etc/passwd and etc/shadow')
    return out


def md5crypt(password: str, salt: str) -> str:
    """Portable FreeBSD/glibc MD5-crypt, compatible with Linux $1$ hashes."""
    pw = password.encode('utf-8')
    sb = salt.encode('ascii')[:8]
    ctx = hashlib.md5()
    ctx.update(pw + b'$1$' + sb)
    alt = hashlib.md5(pw + sb + pw).digest()
    ctx.update((alt * ((len(pw)//16)+1))[:len(pw)])
    n = len(pw)
    while n > 0:
        ctx.update(b'\x00' if n & 1 else pw[:1])
        n >>= 1
    final = ctx.digest()
    for i in range(1000):
        ctx = hashlib.md5()
        ctx.update(pw if i & 1 else final)
        if i % 3:
            ctx.update(sb)
        if i % 7:
            ctx.update(pw)
        ctx.update(final if i & 1 else pw)
        final = ctx.digest()

    def b64_crypt(n: int, count: int) -> str:
        chars = []
        for _ in range(count):
            chars.append(CRYPT_B64[n & 63])
            n >>= 6
        return ''.join(chars)

    groups = ((0, 6, 12, 4), (1, 7, 13, 4), (2, 8, 14, 4),
              (3, 9, 15, 4), (4, 10, 5, 4), (0, 0, 11, 2))
    encoded = ''
    for a, b, c, count in groups:
        if count == 2:
            v = final[c]
        else:
            v = (final[a] << 16) | (final[b] << 8) | final[c]
        encoded += b64_crypt(v, count)
    return '$1$' + salt[:8] + '$' + encoded


def main() -> None:
    ap = argparse.ArgumentParser(description='Offline extraction of root/admin account hashes from own Wanscam dump')
    ap.add_argument('source', type=Path, help='wanscam_full_flash_16MiB.bin or extracted rootfs .tar.gz')
    ap.add_argument('--wordlist', type=Path, help='optional local password candidates, one password per line')
    ap.add_argument('--prompt', action='store_true', help='securely prompt for one additional candidate to verify')
    ap.add_argument('--out', type=Path, help='private results directory, default: Wanscam_Private next to script')
    args = ap.parse_args()
    if not args.source.is_file():
        ap.error(f'File not found: {args.source}')
    source = args.source
    extracted = read_from_tar(source) if tarfile.is_tarfile(source) else read_from_flash(source)
    passwd = {line.split(':', 1)[0]: line for line in extracted['etc/passwd'].decode('utf-8', 'replace').splitlines() if ':' in line}
    shadow = {parts[0]: parts[1] for line in extracted['etc/shadow'].decode('utf-8', 'replace').splitlines() if len(parts := line.split(':')) >= 2}
    output = args.out or (Path(__file__).resolve().parent / 'Wanscam_Private')
    output.mkdir(parents=True, exist_ok=True)
    secret_file = output / 'accounts_private.txt'
    with secret_file.open('w', encoding='utf-8') as fh:
        fh.write('# LOCAL ONLY. Linux password hashes, not plaintext passwords.\n')
        fh.write('# WARNING: Keep this file private.\n')
        for user in ('root', 'admin'):
            fh.write(f'[{user}]\n')
            fh.write('passwd: ' + passwd.get(user, '(missing)') + '\n')
            fh.write('shadow: ' + (user+':'+shadow[user]) if user in shadow else 'shadow: (missing)')
            fh.write('\n\n')
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        pass

    candidates = []
    if args.wordlist:
        if not args.wordlist.is_file():
            ap.error(f'Wordlist not found: {args.wordlist}')
        candidates = [line.rstrip('\r\n') for line in args.wordlist.read_text(encoding='utf-8-sig', errors='replace').splitlines() if line and not line.lstrip().startswith('#')]
        candidates.insert(0, '')
    if args.prompt:
        import getpass
        candidates.append(getpass.getpass('Candidate password (not echoed): '))

    result_file = output / 'verified_passwords_private.txt'
    discovered = []
    for user in ('root', 'admin'):
        h = shadow.get(user, '')
        if not h.startswith('$1$'):
            print(f'{user}: hash algorithm not supported or account locked')
            continue
        salt = h.split('$', 3)[2]
        found = None
        for candidate in dict.fromkeys(candidates):
            if hmac.compare_digest(md5crypt(candidate, salt), h):
                found = candidate
                discovered.append((user, candidate))
                break
        print(f'{user}: MD5-crypt hash extracted; password ' + ('VERIFIED from supplied candidates' if found is not None else 'not recovered'))
    if discovered:
        with result_file.open('w', encoding='utf-8') as fh:
            for user, password in discovered:
                fh.write(f'{user}: {password}\n')
        try:
            os.chmod(result_file, 0o600)
        except OSError:
            pass
        print('Verified plaintext candidates saved locally:', result_file)
    print('Private hashes saved locally:', secret_file)
    print('NO camera connections were made; source image was not modified.')


if __name__ == '__main__':
    main()