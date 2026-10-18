# Wanscam / Hipcam — firmware reverse-engineering report

**Source:** `wanscam_full_flash_16MiB.bin`, uploaded by the camera owner, October 2026.  
**SHA-256 (whole image):** `d208e94b681c5d0b63d4892db9f0e450c4b216b8c962293dc0be784c305881f5`  
**Image size:** 16,777,216 bytes (16 MiB).  
**Method:** Offline, read-only analysis. No changes made to the original firmware image or the camera.

## 1. MTD image layout

| Offset (hex) | Device | Name | Size | MD5 | SHA-256 |
|---|---|---|---:|---|---|
| `000000–05FFFF` | mtd0 | boot | 393,216 | `43afe876868aa1ee26da32edd3841ed9` | `faaa7e5a71a343c3adf23003cdd779d01ab69bc002faed9e6afb1b1930db0f8e` |
| `060000–21FFFF` | mtd1 | kernel | 1,835,008 | `a9c3116ae0746d5030c32cd2324fe7cf` | `8e05986d3b275cfce828bba04835ef3d6fe8cf130ce614947553b60a6b68746d` |
| `220000–FFFFFF` | mtd2 | rootfs | 14,548,992 | `545fc15ce58bc5a0f70b9bcda4bb22cb` | `2e90a38ecf993257e501f1a75c067c242d71d67537e9b96b980f8c8ae7429ecb` |

The image is assembled by concatenating Linux MTD read-only partition dumps, **not** an independent electrical raw read of the memory chip. It covers exactly the three reported partitions; it does not capture non-MTD storage or any hardware-only data. The live writable JFFS2 could change during the multi-stage capture, so the concatenation is **not an atomic filesystem snapshot**. Suitable for reverse engineering; do not treat it as a verified flashable recovery image.

## 2. Bootloader and kernel

- ARM executable code at offset `0x0`.
- U-Boot banner: **`U-Boot 2010.06 (Mar 26 2016 - 14:05:49)`**.
- Bootloader strings include **`HI3518EV200`**, HiSilicon memory-controller / SPI Flash routines, and SPI NOR/NAND support. This strongly suggests the **HiSilicon HI3518EV200** hardware family, without proving the precise PCB/chip marking or type of the physical flash installed.
- Kernel at `0x60000` starts with standard U-Boot **uImage** magic `0x27051956`.
- uImage name **`Linux-3.4.35`**, ARM, Linux kernel, uncompressed uImage payload; load / entry `0x80008000`.
- uImage timestamp: **2016-05-17 07:57:01 UTC**.
- uImage payload 1,832,528 bytes. Both **uImage header CRC32 and payload CRC32 verified successfully**.

## 3. Root filesystem

- JFFS2 starts at `0x220000` (JFFS2 magic `0x1985`).
- A read-only parser validated CRCs for JFFS2 node headers, directory entries and inode data, and decompressed nodes using uncompressed, Zlib and LZO encodings.
- Counts: **6,388 valid JFFS2 nodes** (716 directory entries, 5,621 inode nodes, 51 cleanmarkers), **655 extracted regular files / symlinks**, **zero decompression errors**.
- Important limitations: The tree reconstruction selects latest visible inode versions and directory entries from a live image; this is not a complete JFFS2 garbage-collection or forensic deleted-file reconstruction. Inconsistent captures remain possible.
- Cross-check: Files `web/initializemain.html` (3,442 bytes) and `web/js/initializemain.js` (2,895 bytes) are **byte-for-byte identical** to the copies previously downloaded from the camera HTTP server.

## 4. Telnet startup and authentication — key findings

- `/mnt/mtd/ipc/run` defines `chkdebug()` that reads `tenable` from `/mnt/mtd/ipc/conf/config_debug.ini` and starts `telnetd` when it equals `1`. The call to `chkdebug()` is part of the normal startup sequence.
- The extracted `config_debug.ini` has **`tenable = "1"`**, consistent with our enabling Telnet via a modified configuration backup.
- `/usr/sbin/telnetd`, `/bin/login` and `/bin/su` are **symbolic links to `/bin/busybox`**; they are not separate independent Telnet/login binaries.
- `/etc/passwd` lists **`root` (UID 0)** and **`admin` (UID 501)**. `/etc/shadow` contains distinct password hashes in **MD5-crypt (`$1$`)** format; secret hash values are intentionally excluded here.
- `/etc/securetty` permits `console`, `tty1`–`tty5`, and `ttyS000`, but **does not list Telnet pseudo-terminals (`pts/*`)**. This offers a concrete explanation for why direct `root` Telnet login could be refused even when the account exists; runtime behavior still needs checking.
- Earlier live output `uid=501(admin) gid=501(admin) euid=0(root)` confirms an effective-root context for that shell; **the precise code path causing real/effective UID divergence is not yet proven**.

## 5. Web / CGI architecture

- `/mnt/mtd/ipc/ipc_server` is an ARM ELF application of approximately 1.7 MiB. Static strings within this binary include **`backup.cgi`, `restore.cgi`, `upgrade.cgi`, `param.cgi`**, along with the internal names `HI_CGI_Backup` and `HI_CGI_Telnet_Cfg`.
- No standalone CGI executable files were found under the extracted web directory. The evidence indicates the endpoint handling is built into the camera service rather than independent shell CGI scripts. This inference can be confirmed through static function analysis if needed.
- This agrees with previously observed successful camera-side configuration backup and restore operations.
- The precise backend handling of the 128-byte backup trailer, its integrity checks and hidden diagnostic operations has **not yet been established**. No assertion is made that it is unsigned or safe to modify arbitrarily.

## 6. Main targets for deeper offline RE

| File | Goal |
|---|---|
| `mnt/mtd/ipc/ipc_server` | CGI dispatch; backup/restore; settings, users; native telnet control |
| `mnt/mtd/ipc/libhichip.so` | Platform library and camera API integration |
| `bin/busybox` | Authentication / login implementation in this image |
| `etc/passwd`, `etc/shadow`, `etc/securetty` | Login policy, account layout (keep private) |
| `mnt/mtd/ipc/run` | Boot sequence and Telnet enable condition |
| `mnt/mtd/ipc/upgrade` | On-device firmware-upgrade logic |
| `mnt/mtd/ipc/conf/config_debug.ini` | Enabled debug/Telnet settings |
| `mnt/mtd/ipc/web/` | Native CGI URLs invoked by frontend JavaScript |
| `mnt/mtd/ipc/modules/` | Driver names, sensor hardware and SoC indicators |

## 7. Safety / handling

- The extracted tree includes **live device configuration, password hashes, possibly network credentials and other personal settings**. Keep the extracted archive private; do not upload it to a public repository.
- Captured permissions for `/etc/shadow` are `0766` and for `/etc/passwd` are `0666`, unusually permissive on a live network device. These were reconstructed from JFFS2 inode metadata, not invented by the extraction tool.
- After finishing interactive diagnostics, disable Telnet via `tenable = "0"`, verify that TCP 23 is closed, and keep the camera isolated from untrusted devices.
- Retain the original 16-MiB image and the three independently saved MTD partition dumps unchanged. A read from a running, changing JFFS2 is **not** equivalent to a safe hardware-level restore image.

## 8. Reproducible artefacts

- `wanscam_extracted_rootfs.tar.gz`: extracted filesystem; contains sensitive configuration and is for **private** analysis.
- `wanscam_jffs2_extraction.json`: forensic manifest with paths, inode details, file MD5s and extraction statistics.
- `jffs2_extract_wanscam.py`: the read-only parser and reconstruction script. It contains no camera credentials. Its output is for research, not for rebuilding a flashable JFFS2.