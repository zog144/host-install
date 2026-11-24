# Copyright (c) 2026 Alex Black. All rights reserved. Private acceptance installation.
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
BASE=Path('/opt/zog/host-install-issuer-persistence-20261023')
P=Path('/home/certbot-build-owner/certbot-seed')
G=P/'state/image-build/generations/45a81ec3ea473bfa397e546b5c0ec1ae306bf00cb864eaa9a86d94c13c623f2e'
DATA=P/'state/mounts/persistent/db9837a20bf89c5ea01fc8d2fc67cb74/certificate-data'
VIEW=P/'state/image-build/application-software/views/2cf48c9818adf3891b0ee2a348b335b3cf4ffe758cbda88f116866c3adc0e40f'
ART=P/'state/image-build/application-software/artifacts/6975d95a45bb0a9ae6aa7220c4ba41e4f5701c92f47130d0f73aa90ad1496b6d'
RO=[G,VIEW,ART,Path('/opt/zog/certbot-seed-oct21'),P/'companions']
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():
 uuid=subprocess.check_output(['findmnt','-n','-T',str(DATA),'-o','UUID'],text=True).strip()
 assert uuid=='bb1da0c1-2cbf-492f-911c-93fd0083b4a4',uuid
 st=DATA.lstat();assert stat.S_ISDIR(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(1000020,1000020,0o700)
 r=json.loads((P/'state/application-storage/certify-manage.json').read_text())
 assert r['state']=='ready' and not r['cleanup_pending'] and r['storage_id']=='db9837a20bf89c5ea01fc8d2fc67cb74'
 assert r['generation']==G.name and r['definition']['execution_binding']['grant_id']=='d06162e50a899467bb4c58e276ff45c0'
 assert r['definition']['software_binding']['binding_digest']=='sha256:1a331af3fe4cfb7df5c7b1b88155ae786344a44001f22d0c750c9a25261fa697'
 assert h(G/'manifest.json')=='a58645f5d53b3810aae6641b0f2eac4df1c97265151e8b63770e6700e1ec9f58'
 assert h(Path('/etc/zog/certify-policy/policy.json'))=='ce16e100b417526087fc6a1a588effbf3fd4a04dadfd598e49940c75212f7799'
 files=[P/'state/application-storage/certify-manage.json',P/'state/runtime/references.json',P/'application/certify-manage/application.py',G/'manifest.json',VIEW/'manifest.json',ART/'manifest.json',Path('/etc/zog/certify-policy/policy.json'),Path('/etc/zog/execution-identities.json'),Path('/etc/zog/host-bindings.json'),Path('/etc/systemd/system/zog-certbot-seed-root.service'),Path('/usr/local/sbin/zog-certbot-seed-mounts')]
 for p in Path('/opt/zog/certbot-seed-oct21').rglob('*.py'):
  if '.git' not in p.parts:files.append(p)
 hashes={str(p):h(p) for p in sorted(set(files))}
 content={str(p.relative_to(DATA)):h(p) for p in sorted(DATA.rglob('*')) if p.is_file() and not p.is_symlink()}
 return dict(filesystem_uuid=uuid,storage_inode=st.st_ino,storage_owner=[st.st_uid,st.st_gid],storage_mode=oct(stat.S_IMODE(st.st_mode)),hashes=hashes,storage_hashes=content)
def verify_mounts():
 out={}
 for p in RO:
  options=subprocess.check_output(['findmnt','-n','-T',str(p),'-o','OPTIONS'],text=True).strip();assert os.statvfs(p).f_flag & os.ST_RDONLY,(str(p),options);out[str(p)]={'mount_options':options,'kernel_statvfs_read_only':True}
 options=subprocess.check_output(['findmnt','-n','-T',str(DATA),'-o','OPTIONS'],text=True).strip();assert not (os.statvfs(DATA).f_flag & os.ST_RDONLY),options
 return out
if __name__=='__main__':
 assert os.geteuid()==0
 actual=snapshot()
 if sys.argv[1]=='capture':
  with (BASE/'baseline.json').open('x') as f:json.dump(actual,f,indent=2);f.flush();os.fsync(f.fileno())
  print('BASELINE_CAPTURED',len(actual['hashes']),len(actual['storage_hashes']))
 else:
  expected=json.loads((BASE/'baseline.json').read_text());assert actual==expected,'persistent issuer baseline mismatch'
  mounts=verify_mounts()
  print(json.dumps(dict(status='issuer-persistence-guard-passed',boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),files_verified=len(actual['hashes']),storage_files_verified=len(actual['storage_hashes']),filesystem_uuid=actual['filesystem_uuid'],storage_inode=actual['storage_inode'],read_only_mounts=mounts)))
