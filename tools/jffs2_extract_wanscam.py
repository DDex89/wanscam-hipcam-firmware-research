#!/usr/bin/env python3
"""Read-only JFFS2 parser for analysis of personal Wanscam flash dump.
Reconstructs latest known inode versions and directory entries and writes to local analysis tree.
Not intended to produce a flashable filesystem or guarantee a consistent snapshot of live JFFS2.
"""
import os,struct,zlib,ctypes,ctypes.util,collections,json,stat,hashlib,pathlib,argparse
from datetime import datetime, timezone
parser=argparse.ArgumentParser(description='Offline JFFS2 extraction from an owned Wanscam MTD image (Linux / liblzo2 required)')
parser.add_argument('image',type=pathlib.Path,help='16 MiB flash image or standalone rootfs JFFS2')
parser.add_argument('--out',type=pathlib.Path,default=pathlib.Path('wanscam_extracted_rootfs'),help='private output directory')
parser.add_argument('--manifest',type=pathlib.Path,default=None,help='private manifest JSON path')
args=parser.parse_args()
SOURCE=args.image
ROOT=args.out.resolve()
if not SOURCE.is_file():parser.error('Source image not found')
with SOURCE.open('rb') as f:
 data=f.read()
 if len(data)==16*1024*1024:data=data[0x220000:]
 elif data[:2]!=b'\x85\x19':parser.error('Expected 16 MiB flash image or JFFS2 region')
if ROOT.exists() and any(ROOT.iterdir()):parser.error('Output directory must be empty or non-existent')

def crc32(x):return zlib.crc32(x,0xffffffff)^0xffffffff
lib=ctypes.CDLL(ctypes.util.find_library('lzo2'))
lzo=lib.lzo1x_decompress_safe
lzo.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p]
lzo.restype=ctypes.c_int

def dec(compr, b, outlen):
 if compr==0 or compr==4:return b
 if compr==1:return bytes(outlen)
 if compr==6:
  try: return zlib.decompress(b)
  except zlib.error:return zlib.decompress(b,-15)
 if compr==7:
  dst=ctypes.create_string_buffer(outlen)
  src=ctypes.create_string_buffer(b,len(b))
  sz=ctypes.c_size_t(outlen)
  rv=lzo(src,len(b),dst,ctypes.byref(sz),None)
  if rv!=0:raise ValueError(f'LZO error {rv}')
  return dst.raw[:sz.value]
 if compr==2:
  # rtime decompression as in jffs2 rtime algorithm
  positions=[0]*256; d=bytearray(outlen);x=0;i=0
  while i<len(b) and x<outlen:
   value=b[i]; run=b[i+1]; i+=2
   d[x]=value; x+=1
   back=positions[value]; positions[value]=x
   while run and x<outlen:
    d[x]=d[back];x+=1;back+=1;run-=1
  return bytes(d)
 raise ValueError(f'Unsupported JFFS2 compr={compr}')

inodes=collections.defaultdict(list); dirents=collections.defaultdict(list); counts=collections.Counter(); errors=[]; types=collections.Counter()
for off in range(0,len(data)-12,4):
 if data[off:off+2]!=b'\x85\x19': continue
 magic,typ,tot,hcrc=struct.unpack_from('<HHII',data,off)
 if not 12<=tot<=len(data)-off or crc32(data[off:off+8])!=hcrc:continue
 types[hex(typ)]+=1
 if typ==0xe001 and tot>=40:
  pino,ver,ino,mctime,nsize,ftype,unused,node_crc,name_crc=struct.unpack_from('<IIIIBBHII',data,off+12)
  name=data[off+40:off+40+nsize]
  if len(name)!=nsize or crc32(name)!=name_crc:counts['bad_dirent_namecrc']+=1;continue
  # JFFS2 raw dirent node_crc covers first 32 bytes; compare
  if crc32(data[off:off+32])!=node_crc:counts['bad_dirent_nodecrc']+=1;continue
  dirents[(pino,name)].append(dict(ino=ino,version=ver,ftype=ftype,mctime=mctime,offset=off))
  counts['dirent']+=1
 elif typ==0xe002 and tot>=68:
  (ino,ver,mode,uid,gid,isize,atime,mtime,ctime,fragoff,csize,dsize,compr,usercompr,flags,data_crc,node_crc)=struct.unpack_from('<IIIHHIIIIIIIBBHII',data,off+12)
  if csize>tot-68 or csize>0x100000:counts['bad_csize']+=1;continue
  dat=data[off+68:off+68+csize]
  if crc32(dat)!=data_crc:counts['bad_data_crc']+=1;continue
  if crc32(data[off:off+60])!=node_crc:counts['bad_inode_nodecrc']+=1;continue
  inodes[ino].append(dict(ino=ino,version=ver,mode=mode,uid=uid,gid=gid,isize=isize,atime=atime,mtime=mtime,ctime=ctime,fragoff=fragoff,csize=csize,dsize=dsize,compr=compr,dat=dat,offset=off))
  counts['inode']+=1
 else:counts['other']+=1

print('NODE COUNTS',dict(counts),'node types',dict(types),'inodes',len(inodes),'dirnames',len(dirents))
# selected newest directory entry by version and position
links={};children=collections.defaultdict(list)
for (pino,name),xs in dirents.items():
 last=max(xs,key=lambda r:(r['version'],r['offset']))
 if last['ino']:
  children[pino].append((name,last['ino'],last['ftype']))
  links[(pino,name)]=last['ino']

# traverse from root 1. no arbitrary parent ../ entries
seenpaths={}; work=[(1,pathlib.Path('.'))]
while work:
 ino,path=work.pop(0)
 if ino!=1 and ino not in seenpaths:seenpaths[ino]=str(path)
 for name,target,ftype in children.get(ino,[]):
  if b'/' in name or name in (b'.',b'..') or b'\x00' in name:continue
  n=name.decode('utf-8','surrogateescape'); child=path/n
  if target not in seenpaths:
   seenpaths[target]=str(child)
   if ftype==4:work.append((target,child))
print('Reachable',len(seenpaths),'dir count',len([1 for i,p in seenpaths.items() if i in children]))
ROOT.mkdir(parents=True,exist_ok=True)
metadata=[]; decompression_errors=[]
for ino,path_str in sorted(seenpaths.items(),key=lambda x:x[1]):
 path=ROOT/path_str
 xs=inodes.get(ino,[])
 if not xs:continue
 xs.sort(key=lambda r:(r['version'],r['offset']))
 last=xs[-1]
 mode=last['mode']
 if stat.S_ISDIR(mode):
  path.mkdir(parents=True,exist_ok=True)
  continue
 if not(stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
  continue
 size=last['isize']
 if size>100*1024*1024:decompression_errors.append((path_str,'huge size',size));continue
 buf=bytearray(size)
 for x in xs:
  if x['dsize']==0:continue
  try:
   raw=dec(x['compr'],x['dat'],x['dsize'])
   if len(raw)!=x['dsize']:raise ValueError(f'dec bytes {len(raw)} vs dsize {x["dsize"]}')
   off=x['fragoff']; end=min(off+len(raw),size)
   if off<size:buf[off:end]=raw[:end-off]
  except Exception as e:
   decompression_errors.append((path_str,str(e),x['offset'],x['compr'],x['csize'],x['dsize']))
 path.parent.mkdir(parents=True,exist_ok=True)
 if stat.S_ISLNK(mode):
  target=bytes(buf).decode('utf-8','replace')
  try:path.symlink_to(target)
  except OSError:
   path.with_suffix('.symlink.txt').write_text(target)
 elif stat.S_ISREG(mode):
  path.write_bytes(buf)
  try:os.chmod(path,mode&0o777)
  except Exception:pass
 metadata.append(dict(path=path_str,ino=ino,mode=oct(mode),uid=last['uid'],gid=last['gid'],isize=size,versions=len(xs),md5=hashlib.md5(buf).hexdigest() if size else None))
print('FILES WRITTEN',len(metadata),'ERRORS',len(decompression_errors))
print('EXAMPLES OF ERRORS',decompression_errors[:30])
(args.manifest or (ROOT.parent / (ROOT.name + '_manifest_private.json'))).write_text(json.dumps(dict(stats=dict(counts),node_types=dict(types),directories=len(links),files=metadata,errors=decompression_errors),indent=2))
print('Private output directory:', ROOT)
print('Do not upload extracted rootfs or private manifest to a public repository.')