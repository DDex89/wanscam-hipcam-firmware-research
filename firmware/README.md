# Sanitized Wanscam firmware — forensic research bundle

This directory stores a **redacted, non-flashable research artifact** prepared from an owner-supplied Wanscam/Hipcam 2016 MTD dump.

The archive is stored in **14 numbered parts** (GitHub upload-size workaround). Each file has the suffix `.part01` through `.part14`; concatenating them in that order exactly reconstructs the single TAR.GZ file.

## Assemble locally

From the repository root, Windows PowerShell:

```powershell
py .\firmware\reassemble.py
```

Linux/macOS:

```bash
python3 firmware/reassemble.py
```

The script verifies the exact original archive length (**10,558,035 bytes**) and SHA-256:

```text
a82c82210e26e754deb08e499aaf207426446d8e6d8cb9595800a31dcc2d01a9
```

Alternatively, [download a single archive from the associated ChatGPT conversation], if available to you.

## Contents

- `bootloader_mtd0_sanitized.bin` — 384 KiB bootloader image; last 128 KiB scrubbed (all `FF`) to exclude U-Boot environment and board identifiers
- `kernel_mtd1_original.bin` — Linux 3.4.35 uImage as read from flash; not independently rebuilt
- `rootfs/` — logical extracted JFFS2 files with user-supplied configuration values removed, preserving original relative file paths and most structural configuration keys
- `SANITIZATION_MANIFEST.json` — machine-readable record of every modified/cleared file and nested configuration member
- `README_FIRST.md` — restrictions and treatment of each component

See [sanitization report](../docs/SANITIZATION.md) for a human-readable list of modified files.

### Critical warnings

**DO NOT FLASH THIS PACKAGE**. No raw MTD2/JFFS2 image is included, the bootloader board/environment area was overwritten, compiled vendor code was modified to scrub a device MAC and private IP literals, and the original acquisition was made from a running writable JFFS2 filesystem.

This is **best-effort de-identification**, not a formal guarantee: undocumented identifiers could remain in proprietary binaries. Binary components can be subject to third-party copyright and license restrictions. The research tools and reports in this repository should not be treated as a redistribution license for those binaries.