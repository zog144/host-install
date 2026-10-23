"""Dedicated STATE block-device planning and explicit non-resident provisioning.

Planning is read-only. Apply is an explicit root operation against a previously
recorded stable identity and fresh-volume authorization. Reruns reconcile exact
PARTUUID/filesystem UUID results; they never blindly reformat an uncertain disk.
"""
from contextlib import contextmanager
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess

from . import InstallError
from .preflight import assess as assess_target, collect as collect_base
from .state_contract import (ACCOUNTS, CONFIG, canonical, decode, digest,
                             installation_mode, require, validate)
from .state_inspect import accounts_match, assess_mount, directory, mounts, topology
from .state_io import ensure_directory, lock, publish
from .state_provision import prepare_live

MIB = 1024 * 1024
MINIMUM_STATE_BYTES = 64 * MIB
PLAN_KIND = 'zog-non-resident-state-device-plan'
OPERATION_KIND = 'zog-non-resident-state-device-operation'
GPT_LINUX_FILESYSTEM = '0FC63DAF-8483-4772-8E79-3D69D8477DE4'


def _run(command, *, input_text=None, timeout=30):
    return subprocess.run(command, input=input_text, check=True, capture_output=True,
                          text=True, timeout=timeout)


def _extra_inventory():
    result = _run([
        'lsblk', '--json', '--bytes', '--paths', '--list', '--output',
        'NAME,MAJ:MIN,PARTUUID,UUID,FSTYPE,PTTYPE',
    ])
    rows = json.loads(result.stdout).get('blockdevices')
    require(type(rows) is list, 'topology-unavailable', 'invalid lsblk extended inventory')
    out = {}
    for row in rows:
        path = row.get('name')
        require(type(path) is str and path not in out, 'topology-unavailable',
                'duplicate extended device path')
        out[path] = {
            'devno': row.get('maj:min'),
            'partuuid': row.get('partuuid'),
            'uuid': row.get('uuid'),
            'fstype': row.get('fstype'),
            'pttype': row.get('pttype'),
        }
    return out


def collect_inventory():
    """Current-namespace safety inventory with partition/filesystem identities."""
    base = collect_base()
    extra = _extra_inventory()
    devices = []
    for row in base['devices']:
        require(row['path'] in extra and extra[row['path']]['devno'] == row['devno'],
                'topology-changed', row['path'])
        devices.append({**row, **{k: extra[row['path']][k]
                                  for k in ('partuuid', 'uuid', 'fstype', 'pttype')}})
    require(set(extra) == {row['path'] for row in base['devices']},
            'topology-changed', 'lsblk inventories disagree')
    return {**base, 'devices': devices}


def signatures(path):
    """Read-only signature observation. wipefs writes only when explicitly told to."""
    require(type(path) is str and path.startswith('/dev/'), 'device-path', 'block path required')
    result = _run(['wipefs', '--json', '--no-act', '--output',
                   'DEVICE,OFFSET,TYPE,UUID,LABEL', path])
    value = json.loads(result.stdout)
    rows = value.get('signatures', [])
    require(type(rows) is list, 'signature-inspection', 'invalid wipefs response')
    normalized = []
    for row in rows:
        require(type(row) is dict, 'signature-inspection', 'invalid signature row')
        normalized.append({
            'offset': row.get('offset'),
            'type': row.get('type'),
            'uuid': row.get('uuid'),
            'label': row.get('label'),
        })
    return sorted(normalized, key=lambda x: (str(x['offset']), str(x['type']),
                                             str(x['uuid']), str(x['label'])))


def _base_inventory(snapshot):
    fields = ('path', 'devno', 'type', 'size', 'read_only',
              'identity', 'parents', 'mounts', 'holders')
    devices = []
    for row in snapshot['devices']:
        item = {k: row[k] for k in fields}
        if 'identities' in row:
            item['identities'] = list(row['identities'])
        devices.append(item)
    return {
        'schema': snapshot['schema'],
        'complete': snapshot['complete'],
        'root_devnos': snapshot['root_devnos'],
        'devices': devices,
    }


def _aliases(row):
    values = row.get('identities')
    if values is None:
        values = [row['identity']] if row.get('identity') is not None else []
    require(type(values) is list and
            all(type(value) is str and value.strip() for value in values) and
            len(values) == len(set(values)),
            'stable-target-identity', 'invalid stable identity aliases')
    require(row.get('identity') is None or row['identity'] in values,
            'stable-target-identity', 'primary identity missing from aliases')
    return values


def _whole_disk_matches(snapshot, identities):
    required = set(identities)
    rows = []
    for row in snapshot['devices']:
        if row['type'] != 'disk' or row['parents']:
            continue
        if required.issubset(set(_aliases(row))):
            rows.append(row)
    return rows


def _descendants(snapshot, target):
    indexed = {row['path']: row for row in snapshot['devices']}
    require(target in indexed, 'device-path', 'target missing')
    result = []
    for row in snapshot['devices']:
        active = set()
        cursor = [row['path']]
        ancestors = set()
        while cursor:
            path = cursor.pop()
            require(path not in active, 'topology-cycle', path)
            active.add(path)
            for parent in indexed[path]['parents']:
                require(parent in indexed, 'topology-unavailable', 'unresolved parent')
                if parent not in ancestors:
                    ancestors.add(parent)
                    cursor.append(parent)
        if target in ancestors:
            result.append(row)
    return result


def _volume_binding(selected_volume_reference, expected_identity):
    require(type(selected_volume_reference) is str and
            0 < len(selected_volume_reference.strip()) <= 256,
            'volume-reference', 'selected volume reference required')
    reference = selected_volume_reference.strip()
    require(type(expected_identity) is str and expected_identity.strip(),
            'stable-target-identity', 'expected stable identity required')
    if reference.startswith('aws-ebs:'):
        volume = reference[len('aws-ebs:'):]
        require(re.fullmatch(r'vol-[0-9a-f]{8,32}', volume) is not None,
                'volume-reference', 'canonical AWS EBS volume ID required')
        provider_identity = 'serial:' + volume.replace('-', '')
        return {
            'reference': reference,
            'method': 'aws-ebs-nvme-serial-v1',
            'provider_identity': provider_identity,
        }
    require(reference == 'identity:' + expected_identity,
            'volume-binding',
            'non-AWS volume reference must repeat the exact stable identity')
    return {
        'reference': reference,
        'method': 'exact-stable-identity-v1',
        'provider_identity': expected_identity,
    }


def _resolve_target(snapshot, expected_identity, selected_volume_reference):
    binding = _volume_binding(selected_volume_reference, expected_identity)
    required = [expected_identity]
    if binding['provider_identity'] not in required:
        required.append(binding['provider_identity'])
    rows = _whole_disk_matches(snapshot, required)
    require(len(rows) == 1, 'stable-target-identity',
            'stable aliases must resolve to exactly one whole disk')
    return rows[0], binding


def build_plan(bundle, snapshot, observed_signatures, expected_identity,
               selected_volume_reference):
    validate(bundle)
    require(installation_mode(bundle['installation']) == 'non-resident',
            'installation-mode', 'non-resident installation required')
    target, binding = _resolve_target(
        snapshot, expected_identity, selected_volume_reference)
    assessment = assess_target(_base_inventory(snapshot), target['path'],
                               expected_identity, MINIMUM_STATE_BYTES)
    require(not _descendants(snapshot, target['path']), 'target-not-fresh',
            'fresh STATE target must have no partitions or mapped descendants')
    require(all(target.get(key) in (None, '') for key in
                ('partuuid', 'uuid', 'fstype', 'pttype')),
            'target-not-fresh', 'fresh STATE target has block metadata')
    require(observed_signatures == [], 'target-signatures',
            'fresh STATE target has existing signatures')
    state = bundle['bootstrap']['state']
    return {
        'schema': 1,
        'kind': PLAN_KIND,
        'installation_id': bundle['installation']['installation_id'],
        'bundle_sha256': digest(bundle),
        'selected_volume_reference': binding['reference'],
        'volume_binding_method': binding['method'],
        'provider_identity': binding['provider_identity'],
        'target_identity': expected_identity,
        'target_observation': {
            'path': target['path'],
            'devno': target['devno'],
            'size': target['size'],
            'identities': sorted(_aliases(target)),
            'inventory_sha256': assessment['inventory_sha256'],
            'signatures': [],
        },
        'state': {
            'state_volume_id': state['state_volume_id'],
            'partition_partuuid': state['partition_partuuid'],
            'filesystem_uuid': state['filesystem_uuid'],
            'filesystem_type': 'ext4',
            'mount_point': '/state',
        },
        'layout': {
            'partition_table': 'gpt',
            'partition_count': 1,
            'partition_type_guid': GPT_LINUX_FILESYSTEM,
            'consume_remaining_device': True,
        },
        'authority': {
            'planning_only': True,
            'formatting_authorized': False,
            'identity_initialization_authorized': False,
        },
    }


def plan_live(bundle, expected_identity, selected_volume_reference):
    snapshot = collect_inventory()
    target, _ = _resolve_target(
        snapshot, expected_identity, selected_volume_reference)
    return build_plan(bundle, snapshot, signatures(target['path']),
                      expected_identity, selected_volume_reference)


def validate_plan(plan, bundle):
    require(type(plan) is dict and set(plan) == {
                'schema', 'kind', 'installation_id', 'bundle_sha256',
                'selected_volume_reference', 'volume_binding_method',
                'provider_identity', 'target_identity', 'target_observation',
                'state', 'layout', 'authority',
            }, 'record-fields', 'unexpected STATE device plan fields')
    require(plan['schema'] == 1 and plan['kind'] == PLAN_KIND,
            'unsupported-schema', PLAN_KIND)
    validate(bundle)
    require(installation_mode(bundle['installation']) == 'non-resident',
            'installation-mode', 'non-resident installation required')
    require(plan['installation_id'] == bundle['installation']['installation_id'] and
            plan['bundle_sha256'] == digest(bundle),
            'plan-binding', 'plan does not match installation bundle')
    require(plan['authority'] == {
                'planning_only': True,
                'formatting_authorized': False,
                'identity_initialization_authorized': False,
            }, 'plan-authority', 'device plan cannot authorize writes')
    state = bundle['bootstrap']['state']
    require(plan['state'] == {
                'state_volume_id': state['state_volume_id'],
                'partition_partuuid': state['partition_partuuid'],
                'filesystem_uuid': state['filesystem_uuid'],
                'filesystem_type': 'ext4',
                'mount_point': '/state',
            }, 'plan-binding', 'STATE identity mismatch')
    require(plan['layout'] == {
                'partition_table': 'gpt',
                'partition_count': 1,
                'partition_type_guid': GPT_LINUX_FILESYSTEM,
                'consume_remaining_device': True,
            }, 'plan-layout', 'unsupported STATE disk layout')
    require(type(plan['target_identity']) is str and plan['target_identity'].strip(),
            'stable-target-identity', 'missing stable identity')
    observation = plan['target_observation']
    require(type(observation) is dict and set(observation) == {
                'path', 'devno', 'size', 'identities',
                'inventory_sha256', 'signatures',
            }, 'record-fields', 'unexpected target observation fields')
    require(type(observation['path']) is str and observation['path'].startswith('/dev/') and
            type(observation['devno']) is str and observation['devno'] and
            type(observation['size']) is int and type(observation['size']) is not bool and
            observation['size'] >= MINIMUM_STATE_BYTES and
            type(observation['identities']) is list and
            observation['identities'] == sorted(set(observation['identities'])) and
            all(type(x) is str and x.strip() for x in observation['identities']) and
            plan['target_identity'] in observation['identities'] and
            plan['provider_identity'] in observation['identities'] and
            type(observation['inventory_sha256']) is str and
            re.fullmatch(r'[0-9a-f]{64}', observation['inventory_sha256']) is not None and
            observation['signatures'] == [],
            'target-observation', 'invalid fresh target observation')
    binding = _volume_binding(plan['selected_volume_reference'],
                              plan['target_identity'])
    require(plan['volume_binding_method'] == binding['method'] and
            plan['provider_identity'] == binding['provider_identity'],
            'volume-binding', 'volume binding mismatch')
    return plan


def _device_state(plan, snapshot):
    """Return pristine/partitioned/formatted only for exact expected topology."""
    target, binding = _resolve_target(
        snapshot, plan['target_identity'], plan['selected_volume_reference'])
    require(binding['provider_identity'] == plan['provider_identity'],
            'volume-binding', 'provider identity changed')
    require(target['size'] == plan['target_observation']['size'],
            'target-changed', 'stable identity resolved to a different-sized device')
    require(sorted(_aliases(target)) == plan['target_observation']['identities'],
            'target-changed', 'stable identity aliases changed')
    assess_target(_base_inventory(snapshot), target['path'], plan['target_identity'],
                  MINIMUM_STATE_BYTES)
    children = _descendants(snapshot, target['path'])
    if not children:
        require(all(target.get(key) in (None, '') for key in
                    ('partuuid', 'uuid', 'fstype', 'pttype')),
                'device-state-uncertain', 'target metadata changed before partitioning')
        require(signatures(target['path']) == [], 'device-state-uncertain',
                'unexpected target signature')
        return 'pristine', target, None

    require(target.get('pttype') == 'gpt' and len(children) == 1,
            'device-state-uncertain', 'unexpected partition topology')
    part = children[0]
    require(part['type'] == 'part' and part.get('partuuid') ==
            plan['state']['partition_partuuid'],
            'device-state-uncertain', 'unexpected STATE partition identity')
    require(not part['mounts'] and not part['holders'] and not part['read_only'],
            'device-state-uncertain', 'STATE partition is in use or read-only')
    fstype, uuid = part.get('fstype'), part.get('uuid')
    if fstype in (None, '') and uuid in (None, ''):
        require(signatures(part['path']) == [], 'device-state-uncertain',
                'unexpected signature before formatting')
        return 'partitioned', target, part
    require(fstype == 'ext4' and uuid == plan['state']['filesystem_uuid'],
            'device-state-uncertain', 'unexpected filesystem identity')
    return 'formatted', target, part


def _operation_directory(path):
    require(os.geteuid() == 0, 'root-required', 'STATE device apply requires root')
    path = Path(path).absolute()
    require(path.name not in ('', '.', '..') and
            str(path) != '/state' and not str(path).startswith('/state/'),
            'unsafe-path', 'trusted non-STATE operation directory required')
    parent = directory(str(path.parent))
    try:
        st = os.fstat(parent)
        require(st.st_uid == st.st_gid == 0 and not stat.S_IMODE(st.st_mode) & 0o022,
                'operation-directory', 'operation parent must be root-owned and not writable by others')
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent)
    finally:
        os.close(parent)
    st = os.fstat(fd)
    require((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (0, 0, 0o700),
            'operation-directory', 'operation directory must be root:root 0700')
    return path, fd


def _load_operation(fd):
    try:
        child = os.open('operation.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(child)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0 and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1,
                'operation-record', 'unsafe operation record')
        data = b''
        while len(data) <= 65536:
            part = os.read(child, 65537 - len(data))
            if not part:
                break
            data += part
        require(len(data) <= 65536, 'operation-record', 'operation record too large')
        return decode(data)
    finally:
        os.close(child)


def _write_operation(fd, value):
    pending = '.pending.operation.json'
    try:
        os.unlink(pending, dir_fd=fd)
    except FileNotFoundError:
        pass
    child = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=fd)
    try:
        os.fchmod(child, 0o600)
        data = canonical(value)
        view = memoryview(data)
        while view:
            written = os.write(child, view)
            require(written > 0, 'short-write', 'operation record')
            view = view[written:]
        os.fsync(child)
    finally:
        os.close(child)
    os.replace(pending, 'operation.json', src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def _new_operation(plan):
    return {
        'schema': 1,
        'kind': OPERATION_KIND,
        'plan_sha256': digest(plan),
        'installation_id': plan['installation_id'],
        'target_identity': plan['target_identity'],
        'state_volume_id': plan['state']['state_volume_id'],
        'phase': 'planned',
    }


def _validate_operation(value, plan):
    require(type(value) is dict and set(value) == {
                'schema', 'kind', 'plan_sha256', 'installation_id',
                'target_identity', 'state_volume_id', 'phase',
            }, 'operation-record', 'unexpected operation fields')
    require(value['schema'] == 1 and value['kind'] == OPERATION_KIND,
            'operation-record', 'unsupported operation record')
    require(value['plan_sha256'] == digest(plan) and
            value['installation_id'] == plan['installation_id'] and
            value['target_identity'] == plan['target_identity'] and
            value['state_volume_id'] == plan['state']['state_volume_id'],
            'operation-record', 'operation binding mismatch')
    require(value['phase'] in ('planned', 'partitioned', 'formatted', 'mounted',
                               'configured', 'prepared'),
            'operation-record', 'unknown operation phase')
    return value


def _advance(fd, operation, phase):
    order = ['planned', 'partitioned', 'formatted', 'mounted', 'configured', 'prepared']
    require(order.index(phase) >= order.index(operation['phase']),
            'operation-regression', 'operation phase cannot move backward')
    value = {**operation, 'phase': phase}
    _write_operation(fd, value)
    return value


def _partition(target, partuuid):
    sfdisk = shutil.which('sfdisk')
    require(sfdisk is not None, 'tool-missing', 'sfdisk required')
    script = ('label: gpt\n'
              'unit: sectors\n\n'
              f'type={GPT_LINUX_FILESYSTEM}, uuid={partuuid}, name=ZOG-STATE\n')
    _run([sfdisk, '--lock=yes', '--wipe=never', '--wipe-partitions=never',
          target], input_text=script, timeout=60)
    partprobe = shutil.which('partprobe')
    if partprobe is not None:
        _run([partprobe, target], timeout=30)
    udevadm = shutil.which('udevadm')
    if udevadm is not None:
        _run([udevadm, 'settle', '--timeout=30'], timeout=35)


def _format(partition, filesystem_uuid):
    mkfs = shutil.which('mkfs.ext4')
    require(mkfs is not None, 'tool-missing', 'mkfs.ext4 required')
    _run([mkfs, '-F', '-U', filesystem_uuid, '-L', 'ZOG-STATE', partition],
         timeout=120)
    udevadm = shutil.which('udevadm')
    if udevadm is not None:
        _run([udevadm, 'settle', '--timeout=30'], timeout=35)


def _safe_mountpoint():
    path = Path('/state')
    if path.exists():
        require(path.is_dir() and not path.is_symlink(), 'state-mountpoint',
                '/state must be a real directory')
        st = path.stat()
        require((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (0, 0, 0o755),
                'state-mountpoint', '/state must be root:root 0755')
        require(not any(path.iterdir()), 'state-mountpoint',
                'unmounted /state must be empty')
    else:
        path.mkdir(mode=0o755)
        os.chown(path, 0, 0)
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    require(not any(row['target'] == '/state' for row in
                    mounts(Path('/proc/self/mountinfo').read_text())),
            'state-already-mounted', '/state unexpectedly mounted before activation')


def _mount_unit(plan):
    return (
        '# Generated by host-install non-resident STATE provisioning.\n'
        '[Unit]\n'
        'Description=Zog persistent STATE\n'
        'Before=host-install-prepare.service\n\n'
        '[Mount]\n'
        f"What=/dev/disk/by-partuuid/{plan['state']['partition_partuuid']}\n"
        'Where=/state\n'
        'Type=ext4\n'
        'Options=rw,nodev,nosuid\n\n'
        '[Install]\n'
        'WantedBy=local-fs.target\n'
    ).encode('utf-8')


def _verify_expected_mount(plan):
    return assess_mount(
        mounts(Path('/proc/self/mountinfo').read_text()),
        topology(),
        {
            'partition_partuuid': plan['state']['partition_partuuid'],
            'filesystem_uuid': plan['state']['filesystem_uuid'],
        },
        f"{os.major(os.stat('/').st_dev)}:{os.minor(os.stat('/').st_dev)}",
    )


def _install_mount_unit(plan):
    _safe_mountpoint()
    system = os.open('/etc/systemd/system', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        publish(system, 'state.mount', _mount_unit(plan), 0o644)
    finally:
        os.close(system)
    _run(['systemctl', 'daemon-reload'])
    _run(['systemctl', 'enable', '--now', 'state.mount'], timeout=60)
    return _verify_expected_mount(plan)


def _lookup_group(name, gid):
    try:
        by_name = grp.getgrnam(name)
    except KeyError:
        by_name = None
    try:
        by_id = grp.getgrgid(gid)
    except KeyError:
        by_id = None
    require(by_name is None or by_name.gr_gid == gid, 'account-collision', name)
    require(by_id is None or by_id.gr_name == name, 'account-collision', str(gid))
    return by_name is not None


def _lookup_user(name, row):
    try:
        by_name = pwd.getpwnam(name)
    except KeyError:
        by_name = None
    try:
        by_id = pwd.getpwuid(row['uid'])
    except KeyError:
        by_id = None
    require(by_name is None or (by_name.pw_uid, by_name.pw_gid, by_name.pw_dir,
                                by_name.pw_shell) ==
            (row['uid'], row['gid'], '/state/' + name, '/usr/sbin/nologin'),
            'account-collision', name)
    require(by_id is None or by_id.pw_name == name, 'account-collision', str(row['uid']))
    return by_name is not None


def ensure_accounts():
    """Create only absent fixed accounts after proving names and IDs are unoccupied."""
    groupadd, useradd = shutil.which('groupadd'), shutil.which('useradd')
    require(groupadd is not None and useradd is not None,
            'tool-missing', 'groupadd and useradd required')
    for name, gid in ACCOUNTS['groups'].items():
        if not _lookup_group(name, gid):
            _run([groupadd, '--gid', str(gid), name])
            require(_lookup_group(name, gid), 'account-create', name)
    for name, row in ACCOUNTS['users'].items():
        if not _lookup_user(name, row):
            supplementary = [
                group_name for group_name, gid in ACCOUNTS['groups'].items()
                if gid in row['groups']
            ]
            command = [
                useradd, '--uid', str(row['uid']), '--gid', str(row['gid']),
                '--home-dir', '/state/' + name, '--shell', '/usr/sbin/nologin',
                '--no-create-home', '--no-user-group',
            ]
            if supplementary:
                command += ['--groups', ','.join(supplementary)]
            command.append(name)
            _run(command)
            require(_lookup_user(name, row), 'account-create', name)
    accounts_match()


def _configuration_directory():
    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    opened = []
    fd = root
    try:
        for part in ('etc', 'zog', 'host-install'):
            if part == 'etc':
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
            else:
                child = ensure_directory(fd, part, 0, 0, 0o755)
            opened.append(child)
            fd = child
        return fd, (root, *opened[:-1])
    except BaseException:
        for item in reversed(opened):
            try:
                os.close(item)
            except OSError:
                pass
        os.close(root)
        raise


def publish_configuration(bundle, ca_bytes=None):
    ca_bytes = ca_bytes or {}
    expected = {row['registry_id']: row['ca'] for row in bundle['bootstrap']['registries']
                if row['ca'] is not None}
    require(set(ca_bytes) == set(expected), 'ca-set',
            'provide exactly the referenced CA certificates')
    import hashlib
    for name, data in ca_bytes.items():
        require(type(data) is bytes and len(data) <= 65536 and
                hashlib.sha256(data).hexdigest() == expected[name]['sha256'],
                'ca-digest', name)
    fd, parents = _configuration_directory()
    try:
        for name in ('accounts', 'installation'):
            publish(fd, name + '.json', canonical(bundle[name]), 0o444)
        if ca_bytes:
            ca = ensure_directory(fd, 'ca', 0, 0, 0o755)
            try:
                for name, data in ca_bytes.items():
                    publish(ca, name + '.pem', data, 0o444)
            finally:
                os.close(ca)
        publish(fd, 'bootstrap.json', canonical(bundle['bootstrap']), 0o444)
    finally:
        os.close(fd)
        for parent in reversed(parents):
            os.close(parent)


@contextmanager
def _host_transaction_lock():
    """Serialize every STATE device apply on this host, across operation directories."""
    root = directory('/run/lock')
    try:
        st = os.fstat(root)
        require(st.st_uid == 0 and st.st_gid == 0 and not stat.S_IMODE(st.st_mode) & 0o002,
                'transaction-lock', '/run/lock must be root-owned and not world-writable')
        with lock(root, 'zog-host-install-state-device.lock'):
            yield
    finally:
        os.close(root)


def apply_live(bundle, plan, operation_directory, fresh_volume_id, ca_bytes=None):
    """Provision exactly one fresh dedicated STATE disk; never authorizes identity."""
    require(os.geteuid() == 0, 'root-required', 'STATE device apply requires root')
    validate_plan(plan, bundle)
    require(fresh_volume_id == plan['state']['state_volume_id'],
            'format-authorization', 'explicit fresh STATE volume ID required')

    # Serialize the singleton /state + block-device mutation boundary across every
    # operation directory. The per-operation lock then protects that operation's
    # durable journal and no-replacement metadata publications.
    with _host_transaction_lock():
        path, fd = _operation_directory(operation_directory)
        try:
            with lock(fd, '.state-device.lock'):
                operation = _load_operation(fd)
                if operation is None:
                    operation = _new_operation(plan)
                    _write_operation(fd, operation)
                else:
                    operation = _validate_operation(operation, plan)

                if operation['phase'] in ('mounted', 'configured', 'prepared'):
                    # Revalidate the already-activated device/mount while serialized.
                    _verify_expected_mount(plan)
                else:
                    # If activation completed but the phase record did not, recognize
                    # only the exact expected mount. A different /state is a hard failure.
                    if operation['phase'] == 'formatted' and any(
                            row['target'] == '/state'
                            for row in mounts(Path('/proc/self/mountinfo').read_text())):
                        _verify_expected_mount(plan)
                        operation = _advance(fd, operation, 'mounted')
                    else:
                        # First authoritative apply observation: after both host-wide
                        # and operation locks. Re-resolve provider + stable aliases and
                        # require one whole disk before any destructive action.
                        snapshot = collect_inventory()
                        observed, target, part = _device_state(plan, snapshot)
                        phase_index = {'planned': 0, 'partitioned': 1, 'formatted': 2}
                        observed_index = {
                            'pristine': 0, 'partitioned': 1, 'formatted': 2
                        }[observed]
                        require(observed_index >= phase_index[operation['phase']],
                                'device-state-uncertain', 'device appears rolled back')
                        if observed_index > phase_index[operation['phase']]:
                            operation = _advance(
                                fd, operation,
                                'partitioned' if observed == 'partitioned'
                                else 'formatted')

                        if observed == 'pristine':
                            require(operation['phase'] == 'planned',
                                    'device-state-uncertain',
                                    'pristine disk after destructive phase')
                            _partition(target['path'],
                                       plan['state']['partition_partuuid'])
                            observed, target, part = _device_state(
                                plan, collect_inventory())
                            require(observed == 'partitioned',
                                    'partition-verification',
                                    'expected STATE partition not observed')
                            operation = _advance(fd, operation, 'partitioned')

                        if observed == 'partitioned':
                            _format(part['path'],
                                    plan['state']['filesystem_uuid'])
                            observed, target, part = _device_state(
                                plan, collect_inventory())
                            require(observed == 'formatted',
                                    'format-verification',
                                    'expected ext4 STATE filesystem not observed')
                            operation = _advance(fd, operation, 'formatted')

                        if operation['phase'] == 'formatted':
                            _install_mount_unit(plan)
                            operation = _advance(fd, operation, 'mounted')

                if operation['phase'] == 'mounted':
                    ensure_accounts()
                    publish_configuration(bundle, ca_bytes)
                    operation = _advance(fd, operation, 'configured')

                if operation['phase'] == 'configured':
                    prepare_live(plan['state']['state_volume_id'])
                    operation = _advance(fd, operation, 'prepared')

                return {
                    'status': 'non-resident-state-prepared',
                    'installation_id': plan['installation_id'],
                    'state_volume_id': plan['state']['state_volume_id'],
                    'target_identity': plan['target_identity'],
                    'provider_identity': plan['provider_identity'],
                    'selected_volume_reference': plan['selected_volume_reference'],
                    'operation': str(path),
                    'phase': operation['phase'],
                    'identity_created': False,
                    'identity_authorized': False,
                    'host_os_boot_owned': False,
                }
        finally:
            os.close(fd)
