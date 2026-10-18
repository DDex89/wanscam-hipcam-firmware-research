# Security and responsible handling

This repository contains **offline research tools and descriptive analysis** of an old network camera firmware. It does **not** contain the **original raw 16 MiB flash dump**, live configuration backups, device-specific password hashes, personal credentials, or private network screenshots. A best-effort **sanitized but non-flashable** derived research bundle is included under `firmware/` and may retain undocumented embedded vendor identifiers.

## Protect private artifacts

- Keep original MTD images, extracted rootfs archives, `/etc/shadow`, `/etc/passwd`, CGI configuration files, and generated account output **outside the Git working tree**.
- `.gitignore` is a safeguard, **not** a substitute for reviewing every staged file (`git diff --cached --stat` and `git diff --cached`).
- If secrets enter Git history, deleting a file in a later commit does not remove them from earlier commits. Rotate compromised credentials and rewrite history as needed.
- Device firmware may include copyrighted components and third-party binaries. This repository intentionally excludes redistributed proprietary firmware.

## Operational notes

The source system ran a legacy HiLinux/BusyBox/Telnet stack. Telnet is unencrypted. Disable it after analysis, isolate the device from untrusted clients, and never expose camera administration interfaces to the Internet.

## Scope

Artifacts describe one owner-supplied image and a particular 2016 firmware build. The extracted filesystem was acquired across multiple reads of a **live writable JFFS2**; it is not an atomic or hardware-validated recovery image. Don't flash derivative images without an independent recovery plan.