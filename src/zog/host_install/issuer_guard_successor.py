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


# Approved replacement digest policy. This adds exactly one permissible change
# to the originally captured snapshot: the *live main unit* SHA-256. The
# issuer storage, mount, generation, grant, policy and all other hashes above
# retain their original assertions and unchanged baseline bytes.
UNIT=Path('/etc/systemd/system/zog-certbot-seed-root.service')
ROLLBACK=Path('/opt/zog/compiler-runtime/rollback')
VERSIONS=Path('/opt/zog/compiler-runtime/versions')
ISSUER='issuer-persistence.conf'
SERVICE=UNIT.name


def _protected(path):
 path=Path(path)
 assert path.is_absolute() and '..' not in path.parts,'unsafe issuer evidence path'
 for parent in [*reversed(path.parents),path]:
  info=parent.lstat()
  assert not stat.S_ISLNK(info.st_mode) and info.st_uid==info.st_gid==0 and not(info.st_mode & 0o022),'unsafe issuer evidence ownership/mode'
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1,'unsafe issuer evidence file'
 raw=path.read_bytes()
 assert len(raw)==info.st_size,'issuer evidence size changed'
 return raw


def _json_strict(data):
 def no_duplicates(pairs):
  value={}
  for key,item in pairs:
   assert key not in value,'duplicate issuer evidence property'
   value[key]=item
  return value
 return json.loads(data,object_pairs_hook=no_duplicates)


def _transactions():
 if not ROLLBACK.exists():
  assert not ROLLBACK.is_symlink(),'unsafe compiler rollback root'
  return
 assert ROLLBACK.is_dir() and not ROLLBACK.is_symlink(),'missing compiler rollback'
 for directory in sorted(ROLLBACK.iterdir()):
  if directory.name.startswith('.'):continue
  if not directory.is_dir() or directory.is_symlink():continue
  if len(directory.name) not in (32,64) or any(c not in '0123456789abcdef' for c in directory.name):continue
  tx=directory/'selection-transaction.json'
  if not tx.exists() and not tx.is_symlink():continue
  obj=_json_strict(_protected(tx))
  assert type(obj) is dict and obj.get('release_id')==directory.name,'foreign compiler transaction'
  if obj.get('service')==SERVICE:yield directory,obj


def _interrupted():
 for directory,tx in _transactions():
  assert tx.get('state') not in ('pending','restoring'),'interrupted compiler unit transition'


def _selected_replacement(actual,expected):
 key=str(UNIT)
 assert type(actual) is dict and type(expected) is dict and set(actual)==set(expected),'issuer baseline schema changed'
 assert type(actual.get('hashes')) is dict and type(expected.get('hashes')) is dict,'issuer baseline hashes missing'
 assert set(actual['hashes'])==set(expected['hashes']) and key in expected['hashes'],'issuer baseline file set changed'
 assert actual['hashes'][key]!=expected['hashes'][key],'issuer replacement is not distinct'
 from compiler_issuer_persistence_binding import verify_selected_replacement_digest
 for name in actual:
  if name!='hashes':assert actual[name]==expected[name],'issuer baseline storage or metadata differs'
 for name,value in actual['hashes'].items():
  if name!=key:assert value==expected['hashes'][name],'issuer protected file changed: '+name
 candidates=[(directory,tx) for directory,tx in _transactions()
             if tx.get('state')=='selected' and tx.get('new_unit_sha256')==actual['hashes'][key]]
 assert len(candidates)==1,'no unique durably selected approved replacement'
 directory,tx=candidates[0]
 assert tx['old_unit_sha256']==expected['hashes'][key],'original issuer main-unit baseline changed'
 approved=_protected(directory/'approved-selection.json')
 selected=_json_strict(approved)
 assert type(selected) is dict and selected.get('release_id')==directory.name,'approved selection release changed'
 service=selected['service']
 assert service.get('name')==SERVICE and service.get('active_unit')==key,'approved live unit differs'
 staged=Path(service['staged_unit'])
 assert staged==VERSIONS/directory.name/'systemd'/SERVICE,'unreviewed staged unit path'
 receipt=_json_strict(_protected(directory/'preservation.json'))
 assert receipt.get('unit_sha256')==expected['hashes'][key],'original issuer receipt differs'
 before=_protected(directory/(SERVICE+'.d')/ISSUER)
 after=_protected(staged.parent/(SERVICE+'.d')/ISSUER)
 approved_sha=tx.get('selection_sha256')
 assert type(approved_sha) is str,'missing approved source selection digest'
 # The imported policy independently checks the exact manifest bytes,
 # protected old/new unit and drop-in metadata and durable selected state.
 evidence=verify_selected_replacement_digest(
     selected,approved_sha,approved,receipt,tx,_protected(UNIT),before,after)
 assert evidence.get('selected_transaction_verified') is True
 assert evidence['approved_replacement_unit_sha256']==actual['hashes'][key]
 assert evidence['original_rollback_unit_sha256']==expected['hashes'][key]
 return evidence


def verify_snapshot(actual,expected):
 # Failing / interrupted selections must not silently fall back to baseline.
 _interrupted()
 if actual==expected:return 'original'
 _selected_replacement(actual,expected)
 return 'reviewed-selected'

if __name__=='__main__':
 assert os.geteuid()==0
 assert len(sys.argv)==2 and sys.argv[1]=='verify','issuer baseline recapture disabled'
 actual=snapshot()
 expected=_json_strict(_protected(BASE/'baseline.json'))
 identity=verify_snapshot(actual,expected)
 # These original backing-mount checks MUST execute for both identities.
 mounts=verify_mounts()
 print(json.dumps(dict(status='issuer-persistence-guard-passed',unit_identity=identity,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),files_verified=len(actual['hashes']),storage_files_verified=len(actual['storage_hashes']),filesystem_uuid=actual['filesystem_uuid'],storage_inode=actual['storage_inode'],read_only_mounts=mounts)))
