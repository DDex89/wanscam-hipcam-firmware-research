# Anonymization manifest / Манифест обезличивания

**Research-only. Not flashable.** Original 16 MiB flash image remains private and unchanged.

The sanitization pipeline never republishes raw JFFS2 pages, which may contain deleted or historical device credentials. Instead, it reconstructs the logical file tree.

- **471** regular files and **184** symbolic links in the extracted logical rootfs
- **56** modification records across configs and compiled literals (some paths may have multiple modifications)
- **6** paths whose file contents were fully cleared (zero bytes)
- **35** nested members sanitized in `mnt/mtd/ipc/config_default.zip`
- `/etc/shadow` hashes were replaced by locked markers and `/etc/passwd` password/GECOS columns neutralized
- All config value fields under `mnt/mtd/ipc/conf/` were blanked/zeroed; keys and sections kept where feasible
- The bootloader range `0x40000`–`0x5FFFF` was replaced with `0xFF` to suppress persistent U-Boot settings
- The kernel was preserved as an original vendor binary (non-exhaustive screening only)
- Compiled binaries can contain undocumented encoded identifiers; **no complete anonymity guarantee**

## Exact modified paths / Изменённые пути

| Path | Sanitization action |
|---|---|
| `etc/mtab` | runtime mount information removed |
| `etc/passwd` | password and GECOS fields neutralized |
| `etc/shadow` | password hashes replaced by locked account marker |
| `mnt/mtd/RT2870AP.dat` | field values erased; keys/sections retained where possible |
| `mnt/mtd/RT2870STA.dat` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/TZ` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_3thddns.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_action.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_alarm.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_alarm_token.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_com485.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_cover.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_custom.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_debug.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_defaultimage.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_devices.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_devtype.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_devtypese.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_encode.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_facddns.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_image.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_md.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_net.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_ntp.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_obj_push.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_objsave.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_onvif.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_osd.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_platform.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_priv.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_ptz.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_recsnap.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_run3g.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_schedule.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_sysinfo.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_timer.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_user.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_videoex.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/config_wifiex.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/ipcam_upnp.xml` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/resolv.conf` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/udhcpc/default.bound` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/udhcpc/default.deconfig` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/udhcpc/default.leasefail` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/udhcpc/default.renew` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/udhcpc/default.script` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/udhcps/udhcpd.conf` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/conf/wifi.conf` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/config_default.zip` | all nested configuration files sanitized and re-zipped |
| `mnt/mtd/ipc/web/web.ini` | field values erased; keys/sections retained where possible |
| `mnt/mtd/ipc/setnet` | device MAC literal neutralized in executable or text |
| `mnt/mtd/ipc/wifi_wps.sh` | private network IP literal replaced with documentation address |
| `mnt/mtd/ipc/run` | private network IP literal replaced with documentation address |
| `mnt/mtd/ipc/wifi_setsmart.sh` | private network IP literal replaced with documentation address |
| `mnt/mtd/ipc/ipc_server` | private network IP literal replaced with documentation address |
| `mnt/mtd/ipc/chg_net.sh` | private network IP literal replaced with documentation address |

## Cleared paths / Обнулённые файлы

| Path | Reason |
|---|---|
| `home/admin/.ash_history` | Interactive shell command history |
| `tmp/mtd0_probe.bin` | Temporary bootloader acquisition probe |
| `tmp/tftp-8k.bin` | Temporary acquisition transfer test |
| `tmp/tftp-test.txt` | Temporary acquisition transfer test |
| `var/lib/misc/udhcpd.leases` | Dynamic DHCP lease state |
| `var/run/utmp` | Prior login/session records |

## Sanitized nested ZIP members / Файлы внутри ZIP

- `mnt/mtd/ipc/conf/config_videoex.ini`
- `mnt/mtd/ipc/conf/config_encode.ini`
- `mnt/mtd/ipc/conf/config_custom.ini`
- `mnt/mtd/ipc/conf/config_osd.ini`
- `mnt/mtd/ipc/conf/ipcam_upnp.xml`
- `mnt/mtd/ipc/conf/config_schedule.ini`
- `mnt/mtd/ipc/conf/config_run3g.ini`
- `mnt/mtd/ipc/conf/config_sysinfo.ini`
- `mnt/mtd/ipc/conf/config_action.ini`
- `mnt/mtd/ipc/conf/config_timer.ini`
- `mnt/mtd/ipc/conf/config_objsave.ini`
- `mnt/mtd/ipc/conf/config_com485.ini`
- `mnt/mtd/ipc/conf/config_recsnap.ini`
- `mnt/mtd/ipc/conf/resolv.conf`
- `mnt/mtd/ipc/conf/config_image.ini`
- `mnt/mtd/ipc/conf/config_devices.ini`
- `mnt/mtd/ipc/conf/config_onvif.ini`
- `mnt/mtd/ipc/conf/udhcpc/default.bound`
- `mnt/mtd/ipc/conf/udhcpc/default.script`
- `mnt/mtd/ipc/conf/udhcpc/default.deconfig`
- `mnt/mtd/ipc/conf/udhcpc/default.leasefail`
- `mnt/mtd/ipc/conf/udhcpc/default.renew`
- `mnt/mtd/ipc/conf/udhcps/udhcpd.conf`
- `mnt/mtd/ipc/conf/config_net.ini`
- `mnt/mtd/ipc/conf/config_wifiex.ini`
- `mnt/mtd/ipc/conf/config_md.ini`
- `mnt/mtd/ipc/conf/config_ntp.ini`
- `mnt/mtd/ipc/conf/config_3thddns.ini`
- `mnt/mtd/ipc/conf/TZ`
- `mnt/mtd/ipc/conf/config_cover.ini`
- `mnt/mtd/ipc/conf/config_ptz.ini`
- `mnt/mtd/ipc/conf/config_alarm.ini`
- `mnt/mtd/ipc/conf/config_debug.ini`
- `mnt/mtd/ipc/conf/wifi.conf`
- `mnt/mtd/ipc/conf/config_user.ini`

## Integrity and verification

- Expected reassembled archive length: **10,558,035 bytes**
- Expected SHA-256: `a82c82210e26e754deb08e499aaf207426446d8e6d8cb9595800a31dcc2d01a9`
- Exact original known-value comparison: no matches found for selected original password hashes, IPs, MACs or device identifiers.
- Audit is limited to inspected keys and visible byte sequences; **no guarantee against proprietary binary metadata**.
- Vendor binaries may be copyrighted; verify redistribution rights before rehosting.