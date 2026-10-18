#!/usr/bin/env python3
"""Reassemble byte-for-byte verified sanitized Wanscam research archive."""
from pathlib import Path
import hashlib

HERE=Path(__file__).resolve().parent
NAME='wanscam_firmware_sanitized_research.tar.gz'
SHA256='a82c82210e26e754deb08e499aaf207426446d8e6d8cb9595800a31dcc2d01a9'
SIZE=10558035
PARTS=14
paths=[HERE/f'{NAME}.part{i:02d}' for i in range(1,PARTS+1)]
missing=[p.name for p in paths if not p.is_file()]
if missing:
    raise SystemExit('Missing part(s): '+', '.join(missing))
import tempfile
out=HERE/NAME
with tempfile.NamedTemporaryFile(prefix=NAME+'.',suffix='.tmp',dir=HERE,delete=False) as dest:
    partial=Path(dest.name)
    h=hashlib.sha256();n=0
    for p in paths:
        with p.open('rb') as src:
            while True:
                b=src.read(1024*1024)
                if not b:break
                dest.write(b);h.update(b);n+=len(b)
if n!=SIZE or h.hexdigest()!=SHA256:
    partial.unlink(missing_ok=True)
    raise SystemExit(f'Integrity FAILED: {n} bytes, sha256={h.hexdigest()}')
partial.replace(out)
print('OK:',out,'bytes:',n,'SHA256:',h.hexdigest())