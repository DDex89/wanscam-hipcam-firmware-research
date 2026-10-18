# Wanscam / Hipcam Firmware Research

Reverse engineering and read-only recovery research for a 2016-era Wanscam/Hipcam IP camera, with evidence pointing to the **HiSilicon HI3518EV200** family.

> **Scope:** independent analysis of an owner-provided 16 MiB MTD image. **No firmware, device credentials, or live configuration dumps are distributed here.**

## Verified findings

| Component | Offset | Size | Notes |
|---|---:|---:|---|
| Bootloader (`mtd0`) | `0x000000` | 384 KiB | U-Boot 2010.06; ARM |
| Kernel (`mtd1`) | `0x060000` | 1.75 MiB | uImage, Linux 3.4.35; CRCs verified |
| Rootfs (`mtd2`) | `0x220000` | 13.875 MiB | JFFS2, Zlib/LZO/uncompressed nodes |

- Full image length: **16,777,216 bytes (16 MiB)**.
- SHA-256 of the analyzed owner-provided image: `d208e94b681c5d0b63d4892db9f0e450c4b216b8c962293dc0be784c305881f5`.
- Firmware version reported by the device: `V11.6.5.1.1-20161213`.
- `config_debug.ini` contains a `tenable` setting, which is read by the startup script to launch `telnetd` when enabled.
- CGI handlers such as `backup.cgi` and `restore.cgi` are implemented in the ARM ELF `ipc_server`; static function analysis established the layout of the non-GZIP 128-byte trailer appended to configuration backups.

These findings relate to the examined firmware; they do not establish compatibility with every similarly branded camera.

## Contents

- [`docs/flash_and_jffs2_analysis_EN.md`](docs/flash_and_jffs2_analysis_EN.md) — detailed flash layout, filesystems and authorization research.
- [`docs/ipc_server_reverse_engineering_RU.md`](docs/ipc_server_reverse_engineering_RU.md) — ARM CGI static-analysis report, backup/restore validation and trailer format.
- [`tools/wanscam_backup_trailer_inspect.py`](tools/wanscam_backup_trailer_inspect.py) — inspect owner-held configuration backups offline.
- [`tools/wanscam_accounts_local.py`](tools/wanscam_accounts_local.py) — extract system-account hashes locally from an owned image and optionally verify owner-supplied candidates; creates **private output**.
- [`tools/jffs2_extract_wanscam.py`](tools/jffs2_extract_wanscam.py) — JFFS2 parser/extractor for Linux hosts with `liblzo2`.
- [`README_RU.md`](README_RU.md) — Russian documentation.

## Usage

Windows PowerShell, Python 3.8+ (no extra Python packages):

```powershell
py .\tools\wanscam_backup_trailer_inspect.py "C:\PRIVATE\wanscam_backup.bin"
py .\tools\wanscam_accounts_local.py "C:\PRIVATE\wanscam_full_flash_16MiB.bin" --out "C:\PRIVATE\Wanscam_Private"
```

Full rootfs extraction under Linux with `liblzo2` installed:

```bash
python3 tools/jffs2_extract_wanscam.py /path/to/private/wanscam_full_flash_16MiB.bin --out /path/to/private/wanscam_extracted_rootfs
```

Extraction is read-only with respect to the firmware image but **writes recovered files locally**. Choose an output directory outside your Git repository.

## Important limitations

The three MTD partitions were acquired from a **running camera**. Its writable JFFS2 changed over the acquisition period; the combined image is useful for offline research but **must not be treated as an atomic, validated flashable recovery image**. Some firmware-specific interpretations are based on static reverse engineering and remain subject to further testing.

For responsible handling, see [SECURITY.md](SECURITY.md). No software license has been assigned yet; see [LICENSE-NOTICE.md](LICENSE-NOTICE.md).