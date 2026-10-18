# Исследование прошивки Wanscam / Hipcam

Реверс-инжиниринг старой IP-камеры Wanscam/Hipcam на базе собственного 16-МиБ MTD-образа. Программная платформа — HiLinux, вероятно **HiSilicon HI3518EV200**. Версия прошивки: `V11.6.5.1.1-20161213`.

## Результаты

| Раздел | Смещение | Размер |
|---|---|---:|
| Boot (`mtd0`) | `0x000000` | 384 КиБ |
| Kernel (`mtd1`) | `0x060000` | 1,75 МиБ |
| Rootfs (`mtd2`) | `0x220000` | 13,875 МиБ |

- Загрузчик — U-Boot 2010.06; ядро — Linux 3.4.35; файловая система — JFFS2.
- Разобраны пути `backup.cgi`/`restore.cgi` внутри `ipc_server` и формат 128-байтного служебного хвоста после GZIP.
- Установлено, что флаг `tenable` в `config_debug.ini` используется загрузочным скриптом для запуска Telnet.
- Полный образ, конфигурации, хеши Linux-паролей и частные сетевые настройки **не публикуются**.

## Материалы

- [`docs/flash_and_jffs2_analysis_EN.md`](docs/flash_and_jffs2_analysis_EN.md) — анализ образа Flash, JFFS2 и учётных записей.
- [`docs/ipc_server_reverse_engineering_RU.md`](docs/ipc_server_reverse_engineering_RU.md) — разбор CGI и проверок формата резервного архива.
- [`tools/wanscam_accounts_local.py`](tools/wanscam_accounts_local.py) — локальное извлечение учётных записей владельца из его образа.
- [`tools/wanscam_backup_trailer_inspect.py`](tools/wanscam_backup_trailer_inspect.py) — исследование служебного хвоста архива конфигурации.
- [`tools/jffs2_extract_wanscam.py`](tools/jffs2_extract_wanscam.py) — офлайн-экстрактор JFFS2 (Linux + liblzo2).

## Примеры команд

В Windows PowerShell (все утилиты запускаются **локально**, без подключения к камере):

```powershell
py .\tools\wanscam_accounts_local.py "C:\PRIVATE\wanscam_full_flash_16MiB.bin" --out "C:\PRIVATE\Wanscam_Private"
py .\tools\wanscam_backup_trailer_inspect.py "C:\PRIVATE\wanscam_backup.bin"
```

В Linux (нужна библиотека liblzo2):

```bash
python3 tools/jffs2_extract_wanscam.py /private/wanscam_full_flash_16MiB.bin --out /private/wanscam_extracted_rootfs
```

Не используйте полученный при работе камеры образ как гарантированно пригодный для обратной записи: JFFS2 менялась во время снятия дампа.

**Безопасность:** личные пароли, образ, конфигурации и результаты экстракции хранить вне GitHub. Подробнее — [SECURITY.md](SECURITY.md).