#!/usr/bin/env python3
"""Make a non-flashable, research-only, privacy-redacted Wanscam rootfs bundle.

Designed for an already extracted JFFS2 directory. Never edits the source tree.
All embedded configuration values are replaced, rather than using incomplete
password/SSID heuristics. Produces deterministic-ish tar + audit metadata.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import re
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

ROOT_CONFIG = 'mnt/mtd/ipc/conf/'
DRIVER_CONFIG = {'mnt/mtd/RT2870AP.dat','mnt/mtd/RT2870STA.dat'}
EXACT_CLEARED = {
    'home/admin/.ash_history': 'Interactive shell command history',
    'var/run/utmp': 'Prior login/session records',
    'var/lib/misc/udhcpd.leases': 'Dynamic DHCP lease state',
    'tmp/tftp-test.txt': 'Temporary acquisition transfer test',
    'tmp/tftp-8k.bin': 'Temporary acquisition transfer test',
    'tmp/mtd0_probe.bin': 'Temporary bootloader acquisition probe',
}
INI_TEXT = re.compile(r'^(\s*[^\s#;\[\]=][^=\r\n]*?\s*=\s*)(.*?)(\r?\n?)$')
KEY_VALUE = re.compile(r'^(\s*[^\s#;\[\]=][^=\r\n]*?\s*=\s*)(.*?)(\r?\n?)$')


def masked_ini(data: bytes, filename: str, report: dict) -> bytes:
    src = data.decode('latin-1')
    lines = []
    key_count = 0
    for raw in src.splitlines(keepends=True):
        line = raw.strip()
        nl = '\r\n' if raw.endswith('\r\n') else ('\n' if raw.endswith('\n') else '')
        if not line:
            lines.append(nl); continue
        if line.startswith('[') and line.endswith(']'):
            # Replace section name if it may contain a user-assigned identifier.
            if re.search(r'[\w-]{12,}|\d{2,}[._-]\d+', line):
                # Preserve numbering for indexed sections; otherwise generic identifier.
                safe = re.sub(r'(?<!\w)[0-9a-fA-F]{12,}(?!\w)', 'REDACTED_SECTION', line)
                lines.append(safe+nl)
            else: lines.append(line+nl)
            continue
        if line.startswith(('#',';')):
            # Don't preserve potentially personal comments.
            continue
        m=KEY_VALUE.match(raw)
        if m:
            prefix, val, newline=m.groups()
            name=prefix.split('=',1)[0].strip().lower()
            if name=='tenable' and 'config_debug.ini' in filename:
                masked='"0"' if val.strip().startswith(('"', "'")) else '0'
            elif val.lstrip().startswith(('"', "'")):
                # Avoid retaining any sensitive value, even unknown OEM field names.
                q=val.lstrip()[0]
                masked=q+q
            elif name in {'ipaddr','netmask','gateway','dns','dns1','dns2','start','end','router'}:
                masked='0.0.0.0'
            elif val.strip().lower() in {'true','false'}:
                masked='false'
            else:
                masked='0'
            lines.append(prefix+masked+newline)
            key_count+=1
        elif filename.endswith('.xml'):
            # XML handled separately.
            raise AssertionError('XML in ini parser')
        elif '/' in filename and filename.endswith(('.conf','.script','.bound','.renew','.deconfig','.leasefail')):
            # Generic shell/dhcp material: retain directive names only.
            token=line.split(None,1)[0]
            if re.match(r'^[A-Za-z_][\w-]*$',token):
                lines.append('# SANITIZED: '+token+' [value removed]'+nl)
            else:
                lines.append('# SANITIZED: line removed'+nl)
        else:
            lines.append('# SANITIZED: unrecognized line removed'+nl)
    report['redacted_assignments']+=key_count
    return ''.join(lines).encode('latin-1')


def masked_xml(data: bytes, report: dict) -> bytes:
    from xml.etree import ElementTree as ET
    try:
        root=ET.fromstring(data)
        for el in root.iter():
            if el.text and el.text.strip(): el.text='REDACTED'
            if el.tail and el.tail.strip(): el.tail='\n'
            for k in list(el.attrib):
                if 'schemaLocation' not in k: el.set(k,'REDACTED')
        report['redacted_xml']+=1
        return ET.tostring(root,encoding='utf-8',xml_declaration=True)
    except ET.ParseError:
        report['redacted_xml']+=1
        return b'<?xml version="1.0"?><sanitized reason="source XML could not be safely parsed"/>\n'


def sanitize_config_bytes(name:str,data:bytes,report:dict)->bytes:
    if name.endswith('.xml'):return masked_xml(data,report)
    if name.endswith('/TZ'):return b'UTC0\n'
    if name.endswith('/resolv.conf'):return b'# SANITIZED: DNS configuration removed\n'
    if name.endswith('/web.ini') or name.endswith(('.ini','.dat','.conf')):
        return masked_ini(data,name,report)
    if name.endswith(('default.script','default.bound','default.deconfig','default.leasefail','default.renew')):
        # Drop the script body instead of risking config or hardcoded secrets.
        return b'#!/bin/sh\n# SANITIZED: original DHCP helper removed; non-operational research placeholder\n'
    # Other conf directory files: keep relative name, but not unverified content.
    return b'# SANITIZED: removed original contents\n'


def sanitize_zip(path:Path,report:dict)->bytes:
    source=path.read_bytes(); output=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(source),'r') as zin, zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as zout:
        for info in zin.infolist():
            name=info.filename
            if info.is_dir():zout.writestr(name,b'');continue
            dat=zin.read(info)
            if '/conf/' in name or name.endswith(('.ini','.dat','.conf')):
                dat=sanitize_config_bytes(name,dat,report)
                report['zip_modified'].append(name)
            else:
                # fail closed rather than accidentally retain a private nested blob
                dat=b'SANITIZED: non-configuration content removed\n'
                report['zip_modified'].append(name)
            zout.writestr(name,dat)
    return output.getvalue()


def is_private_path(name:str)->bool:
    return name.startswith(ROOT_CONFIG) or name in DRIVER_CONFIG or name == 'mnt/mtd/ipc/web/web.ini'


def process(original:Path,stage:Path,report_path:Path,release_archive:Path):
    if stage.exists():shutil.rmtree(stage)
    stage.mkdir(parents=True)
    report=dict(archive_kind='sanitized non-flashable filesystem',redacted_assignments=0,redacted_xml=0,modified=[],cleared=[],zip_modified=[],binary_policy='Preserved binary executable and library artifacts, not raw JFFS2 pages')
    for f in sorted(original.rglob('*')):
        n=f.relative_to(original).as_posix();dest=stage/n
        if f.is_symlink():
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.symlink_to(f.readlink())
            continue
        if f.is_dir():dest.mkdir(exist_ok=True,parents=True);continue
        if not f.is_file():continue
        dest.parent.mkdir(exist_ok=True,parents=True)
        data=f.read_bytes();final=data
        if n in EXACT_CLEARED:
            final=b''
            report['cleared'].append({'path':n,'reason':EXACT_CLEARED[n]})
        elif n=='etc/shadow':
            rows=[]
            for l in data.decode('latin-1').splitlines():
                x=l.split(':')
                if len(x)>1:x[1]='!'
                rows.append(':'.join(x))
            final=('\n'.join(rows)+'\n').encode('latin-1')
            report['modified'].append({'path':n,'action':'password hashes replaced by locked account marker'})
        elif n=='etc/passwd':
            rows=[]
            for l in data.decode('latin-1').splitlines():
                x=l.split(':')
                if len(x)>1:x[1]='x'
                if len(x)>4:x[4]=''
                rows.append(':'.join(x))
            final=('\n'.join(rows)+'\n').encode('latin-1')
            report['modified'].append({'path':n,'action':'password and GECOS fields neutralized'})
        elif n=='etc/mtab':
            final=b''
            report['modified'].append({'path':n,'action':'runtime mount information removed'})
        elif n=='mnt/mtd/ipc/config_default.zip':
            final=sanitize_zip(f,report)
            report['modified'].append({'path':n,'action':'all nested configuration files sanitized and re-zipped'})
        elif is_private_path(n):
            final=sanitize_config_bytes(n,data,report)
            report['modified'].append({'path':n,'action':'field values erased; keys/sections retained where possible'})
        if final is data or final==data:
            shutil.copy2(f,dest)
        else:
            dest.write_bytes(final)
            dest.chmod(stat.S_IMODE(f.stat().st_mode))
    # Remove a device MAC that also appears verbatim inside an ELF utility.
    # This is a deliberately narrow patch: binary executable may no longer be
    # functionally identical; the release is for research and is not flashable.
    mac_file=original/'mnt/mtd/ipc/conf/config_priv.ini'
    mac_match=re.search(rb'(?im)^\s*macaddr\s*=\s*[\"\']?([0-9a-f]{2}(?::[0-9a-f]{2}){5})',mac_file.read_bytes())
    if mac_match:
        mac=mac_match.group(1)
        for p in stage.rglob('*'):
            if not p.is_file() or p.is_symlink(): continue
            n=p.relative_to(stage).as_posix()
            if n.startswith(ROOT_CONFIG) or n in DRIVER_CONFIG: continue
            dat=p.read_bytes()
            if mac in dat:
                p.write_bytes(dat.replace(mac,b'00:00:00:00:00:00'))
                report['modified'].append({'path':n,'action':'device MAC literal neutralized in executable or text'})
    # Remove live private network IP literals, which can be compiled into vendor
    # software and shell scripts as well as the active configuration.
    netcfg=original/'mnt/mtd/ipc/conf/config_net.ini'
    netdata=netcfg.read_text('latin-1')
    net_ips=set()
    for line in netdata.splitlines():
        if '=' not in line:continue
        key,val=line.split('=',1)
        if key.strip().lower() not in {'ipaddr','gateway','netmask'}:continue
        value=val.strip().strip('\"\' ')
        if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}',value) and value not in {'0.0.0.0','255.255.255.0'}:
            net_ips.add(value.encode('ascii'))
    for addr in sorted(net_ips,key=len,reverse=True):
        neutral={11:b'203.0.113.1',12:b'203.0.113.10',13:b'203.0.113.100'}.get(len(addr),b'0'*len(addr))
        assert len(addr)==len(neutral)
        for p in stage.rglob('*'):
            if not p.is_file() or p.is_symlink(): continue
            data=p.read_bytes()
            if addr in data:
                p.write_bytes(data.replace(addr,neutral))
                report['modified'].append({'path':p.relative_to(stage).as_posix(),'action':'private network IP literal replaced with documentation address'})
    # sanity: no unchanged configuration files
    for f in original.rglob('*'):
        if f.is_file() and not f.is_symlink():
            n=f.relative_to(original).as_posix()
            if is_private_path(n) and f.read_bytes()==(stage/n).read_bytes():
                raise AssertionError('A config file was accidentally kept unchanged: '+n)
    # symlink audit: links may point outside staging, archive extraction users warned
    report['counts']={'files':sum(f.is_file() and not f.is_symlink() for f in stage.rglob('*')),'symlinks':sum(f.is_symlink() for f in stage.rglob('*')),'directories':sum(f.is_dir() and not f.is_symlink() for f in stage.rglob('*'))}
    report['original_source_files_sha256']='NOT RECORDED to avoid disclosure of sensitive original file fingerprints'
    report_path.parent.mkdir(parents=True,exist_ok=True)
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    with tarfile.open(release_archive,'w:gz',compresslevel=9) as tar:
        tar.add(stage,arcname='wanscam_rootfs_sanitized',recursive=True,filter=lambda m: _scrub_metadata(m))
    report['release_archive_sha256']=hashlib.sha256(release_archive.read_bytes()).hexdigest()
    report['release_archive_bytes']=release_archive.stat().st_size
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'counts':report['counts'],'modified':len(report['modified']),'cleared':len(report['cleared']),'zip_modified':len(report['zip_modified']),'archive_size':release_archive.stat().st_size,'sha256':report['release_archive_sha256']},indent=2))


def _scrub_metadata(m):
    m.uid=m.gid=0;m.uname=m.gname='';m.mtime=0
    return m

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path,help='Already extracted, private rootfs directory')
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    a=parser.parse_args()
    process(a.source,a.stage,a.report,a.archive)