"""Explicit managed-beacon provisioning and offline systemd composition."""
import base64
import csv
import hashlib
import importlib
import importlib.metadata
import io
import os
import re
import stat
import sys
from importlib.resources import files as resource_files
from pathlib import Path
from .state_contract import StateError, canonical, decode, fields, require, sha
from .state_inspect import directory, inspect_live, metadata
from .state_initialize import operations
from .state_io import ensure_directory, lock, publish, raw

# Reviewed consumer templates; changes require interface review, not silent adoption.
CONSUMER_COMMIT = '9e741d9a86bb2fd466ac46b252be0b78528eeff7'
CONSUMER_VERSION = '0.4.11'
CONSUMER_HASHES = {'host-discover-supervisor.socket': 'e2e07d9780f3e24fb32438779806d60d1948130970ac45938184cc2a05cd9db6', 'host-discover-supervisor@.service': '7e559dd696609c4787c9a2711165aa32c1be7ec011636dcd33d837114eecc22a', 'host-discover-beacon.service': '5c82b531eaf548074a2480354eb208496634ffa6b916320632311b71da9fb430'}
AUTHORITY_SOURCE_BLOBS = {'src/zog/host_discover/supervisor.py': '419c56e07e22d2784fca6cb44ccb1e7a4dd54f0f', 'src/zog/host_discover/certificate_assignment.py': 'ac7ef69f6b22bc227c0b1eb05b76c1bf4bd389e2'}
HOST_DISCOVER_MODULE_BLOBS = {
    'zog.host_discover': '58ce5cd1740564637174cc20fec784715c0a205e',
    'zog.host_discover.__main__': '16706bed4b74fec1e5114d4988ebdc5d87833080',
    'zog.host_discover.admission': 'beffaefc3b975babe9ac244ec84cef9b75df6cba',
    'zog.host_discover.beacon': '92122d4490a073dcbc3cded05ac0c681fdb01d6e',
    'zog.host_discover.beacon_state': 'c4855a2076a79f80bb1eafac40939ec9635329dd',
    'zog.host_discover.bootstrap': '9d673f544b8a6cad5791090c579f421d55e2770b',
    'zog.host_discover.box_bridge': '49442741bb1b90d504bce27c115dbe238bf423e2',
    'zog.host_discover.certificate_assignment': 'ac7ef69f6b22bc227c0b1eb05b76c1bf4bd389e2',
    'zog.host_discover.daemon': '46c8b583ee498d91b01cd832446a11f83c622f3e',
    'zog.host_discover.destinations': '03ab9b460a6ce35c3d51dcf37b1fd35c5b24d157',
    'zog.host_discover.gateway': '4b835006e041a9c46346c7ea4aee4878272a8825',
    'zog.host_discover.managed': '2cec3a229c35c5d0bd2bf4b05906a299e0a4484b',
    'zog.host_discover.managed_transport': '386384ade8606797cd7be855e26951be63bac2e1',
    'zog.host_discover.recovery': 'e7c06400c8e1619f757dfe373d67c973238d92b2',
    'zog.host_discover.retry': '1b59ece376adce962d3c9d9de93ba743abae9741',
    'zog.host_discover.roles': '436da585db2442f4943a5887a1b303e9d3f7f2b5',
    'zog.host_discover.supervisor': '419c56e07e22d2784fca6cb44ccb1e7a4dd54f0f',
}
HOST_DISCOVER_SOURCE_FILES = {
    module: (
        'src/zog/host_discover/__init__.py'
        if module == 'zog.host_discover'
        else 'src/' + module.replace('.', '/') + '.py'
    )
    for module in HOST_DISCOVER_MODULE_BLOBS
}
AUTHORITY_PIN_KIND = 'zog-certificate-assignment-authority-pin'
AUTHORITY_PIN_NAME = 'certificate-assignment-authority.json'


def prepare(context, volume, supervisor):
    require(os.geteuid() == 0, 'root-required', 'Explicit root provisioning required')
    require(volume == context.bundle['bootstrap']['state']['state_volume_id'], 'volume-confirmation', 'Exact STATE UUID required')
    # Observe before locking: the producer itself acquires the operations lock.
    observation = supervisor.wire.observe(context)
    require(not observation['recovery_hold'], 'recovery-required', 'Installer hold')
    value = canonical(dict(schema=1, kind='zog-beacon-provisioning', binding=supervisor.fixed(context, observation)))
    with operations(context) as fd, lock(fd, 'beacon-provision.lock'):
        intent = raw(fd, 'beacon-intent.json', links=(1, 2))
        completed = raw(fd, 'beacon-prepared.json', links=(1, 2))
        if completed is not None:
            require(intent == value and completed == value, 'beacon-provision-conflict', 'Provisioning binding changed')
            # Never prepare again once consumed, even if the ledger is missing.
            with supervisor.ledger(context) as (_, ledger):
                require(ledger['binding'] == supervisor.fixed(context, observation), 'beacon-provision-conflict', 'Ledger binding changed')
            publish(fd, 'beacon-prepared.json', value)
        else:
            # An absent receipt cannot adopt an already used journal/ledger.
            with supervisor.stopped_consumer(context):
                home = os.open('host-discover', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=context.fd)
                try:
                    control = os.open('control', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
                    try:
                        require(not os.listdir(control), 'beacon-existing-state', 'Initial provisioning cannot adopt an existing journal')
                    finally: os.close(control)
                finally: os.close(home)
                publish(fd, 'beacon-intent.json', value)
                supervisor.prepare(context, volume)
                publish(fd, 'beacon-prepared.json', value)
        context.recheck()
    return dict(status='beacon-profile-prepared', transport_enabled=False, control_authorized=False)


def prepare_live(volume):
    from zog.host_discover import supervisor
    with inspect_live() as context:
        return prepare(context, volume, supervisor)


def _git_blob(data):
    return hashlib.sha1(
        b'blob ' + str(len(data)).encode('ascii') + b'\0' + data
    ).hexdigest()


def _record_sha256(data):
    return base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).rstrip(b'=').decode()


def _protected_ancestry(path, stop):
    path = Path(path)
    stop = Path(stop)
    require(path.is_absolute() and stop.is_absolute(),
            'host-discover-installed', 'protected path must be absolute')
    try:
        path.relative_to(stop)
    except ValueError:
        require(False, 'host-discover-installed',
                'installed path is outside approved root')
    current = path
    while True:
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and not (info.st_mode & 0o022),
            'host-discover-installed',
            'installed software path is redirected or writable',
        )
        if current == stop:
            break
        current = current.parent


def verify_reviewed_source(discover_source):
    root = Path(discover_source)
    require(root.is_dir() and not root.is_symlink(),
            'host-discover-source', 'reviewed host-discover source unavailable')
    observed = {}
    for module, relative in HOST_DISCOVER_SOURCE_FILES.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                'host-discover-source', 'reviewed host-discover module missing')
        data = path.read_bytes()
        require(0 < len(data) <= 2_000_000,
                'host-discover-source', 'reviewed host-discover module too large')
        blob = _git_blob(data)
        require(blob == HOST_DISCOVER_MODULE_BLOBS[module],
                'host-discover-source',
                'host-discover runtime differs from reviewed successor')
        observed[module] = {
            'path': relative,
            'git_blob': blob,
            'sha256': hashlib.sha256(data).hexdigest(),
        }
    return observed


def verify_installed(*, python_executable='/usr/bin/python3'):
    """Attest exact reviewed host-discover runtime bytes in the aggregate wheel."""
    require(os.geteuid() == 0, 'root-required',
            'installed host-discover attestation requires root')
    require(not os.environ.get('PYTHONPATH'), 'host-discover-installed',
            'inherited PYTHONPATH is not permitted')
    require(not os.environ.get('PYTHONHOME'), 'host-discover-installed',
            'inherited PYTHONHOME is not permitted')
    configured = Path(python_executable)
    require(configured.is_absolute() and configured.exists(),
            'host-discover-installed', 'approved Python executable unavailable')
    running = Path(sys.executable).resolve()
    require(configured.resolve() == running,
            'host-discover-installed',
            'attestation interpreter differs from approved service interpreter')
    _protected_ancestry(running, Path('/'))

    try:
        distribution = importlib.metadata.distribution('zog')
    except importlib.metadata.PackageNotFoundError:
        require(False, 'host-discover-installed',
                'aggregate zog distribution is not installed')
    require(distribution.metadata.get('Name') == 'zog',
            'host-discover-installed', 'unexpected aggregate distribution name')
    root = Path(distribution.locate_file('')).resolve()
    _protected_ancestry(root, Path('/'))
    record_text = distribution.read_text('RECORD')
    require(type(record_text) is str and 0 < len(record_text) <= 4_000_000,
            'host-discover-installed', 'aggregate wheel RECORD missing or excessive')
    rows = {}
    for row in csv.reader(io.StringIO(record_text)):
        require(len(row) == 3 and row[0] not in rows,
                'host-discover-installed', 'invalid aggregate wheel RECORD')
        rows[row[0]] = (row[1], row[2])
    record_files = [
        value for value in distribution.files or ()
        if str(value).endswith('.dist-info/RECORD')
    ]
    require(len(record_files) == 1,
            'host-discover-installed', 'aggregate RECORD path is ambiguous')
    record_path = Path(distribution.locate_file(record_files[0]))
    _protected_ancestry(record_path, root)
    info = record_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'host-discover-installed',
            'aggregate RECORD is not a protected regular file')

    observed = {}
    for module, expected_blob in HOST_DISCOVER_MODULE_BLOBS.items():
        loaded = importlib.import_module(module)
        origin = getattr(loaded, '__file__', None)
        require(type(origin) is str, 'host-discover-installed',
                'loaded host-discover module has no filesystem origin')
        path = Path(origin)
        _protected_ancestry(path, root)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                'host-discover-installed',
                'loaded host-discover module is not a protected regular file')
        data = path.read_bytes()
        blob = _git_blob(data)
        require(blob == expected_blob, 'host-discover-installed',
                'installed host-discover bytes differ from reviewed successor')
        relative = path.resolve().relative_to(root).as_posix()
        require(relative in rows, 'host-discover-installed',
                'host-discover module absent from aggregate RECORD')
        algorithm, separator, encoded = rows[relative][0].partition('=')
        require(separator == '=' and algorithm == 'sha256'
                and encoded == _record_sha256(data),
                'host-discover-installed',
                'aggregate RECORD hash disagrees with host-discover module')
        observed[module] = {
            'origin': str(path.resolve()),
            'git_blob': blob,
            'sha256': hashlib.sha256(data).hexdigest(),
            'record_path': relative,
        }

    package = importlib.import_module('zog.host_discover')
    require(getattr(package, '__version__', None) == CONSUMER_VERSION,
            'host-discover-installed', 'unexpected host-discover version')
    return {
        'schema': 'zog-host-install-host-discover-installed-attestation-v1',
        'status': 'host-discover-installed-software-verified',
        'consumer_commit': CONSUMER_COMMIT,
        'consumer_version': CONSUMER_VERSION,
        'distribution': {
            'name': distribution.metadata['Name'],
            'version': distribution.version,
            'root': str(root),
            'record_origin': str(record_path),
            'record_sha256': hashlib.sha256(record_text.encode()).hexdigest(),
        },
        'python_executable': str(running),
        'pythonpath_present': False,
        'modules': observed,
        'state_modified': False,
        'station_approval_authorized': False,
    }


def stage(discover_source, producer_source, output, executable_directory='/usr/bin', authority_pin=None):
    """Root-owned resumable offline overlay; never enable services or touch STATE."""
    require(os.geteuid() == 0, 'root-required', 'Root-owned composition required')
    require(re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+', executable_directory) is not None,
            'executable-directory', 'Absolute simple directory required')
    files = {}
    for name, expected in CONSUMER_HASHES.items():
        data = (Path(discover_source)/'deployment'/name).read_bytes()
        require(hashlib.sha256(data).hexdigest() == expected, 'consumer-template-changed', name)
        files[name] = data.decode()
    reviewed_modules = verify_reviewed_source(discover_source)
    for relative, expected in AUTHORITY_SOURCE_BLOBS.items():
        data = (Path(discover_source) / relative).read_bytes()
        require(_git_blob(data) == expected,
                'consumer-authority-source-changed', relative)
    pin = None
    if authority_pin is not None:
        path = Path(authority_pin)
        require(path.is_file() and not path.is_symlink(), 'certificate-authority-pin', 'Reviewed authority pin must be a regular file')
        raw_pin = path.read_bytes()
        require(len(raw_pin) <= 4096, 'certificate-authority-pin', 'Authority pin exceeds size bound')
        pin = decode(raw_pin)
        fields(pin, 'schema kind registry_id authority_public_key authority_key_id')
        require(type(pin['schema']) is int and pin['schema'] == 1 and pin['kind'] == AUTHORITY_PIN_KIND and
                type(pin['registry_id']) is str and 1 <= len(pin['registry_id']) <= 64,
                'certificate-authority-pin', 'Unsupported authority pin')
        sha(pin['authority_key_id'])
        from zog.host_identify import signatures
        try:
            key = signatures.public_key(pin['authority_public_key'])
        except (TypeError, ValueError) as exc:
            raise StateError('certificate-authority-pin', 'Invalid Ed25519 authority public key') from exc
        require(signatures.fingerprint(key) == pin['authority_key_id'],
                'certificate-authority-pin', 'Authority key fingerprint mismatch')
    packaged = resource_files(__package__).joinpath('systemd')
    for name in ('host-install-admission.socket','host-install-admission@.service',
                 'host-install-identity.service','host-install-prepare.service'):
        data = packaged.joinpath(name).read_text()
        if producer_source is not None:
            checkout = (Path(producer_source)/'examples/systemd'/name).read_text()
            require(checkout == data, 'producer-template-changed', name)
        files[name] = data
    files['host-discover-beacon.service'] = files['host-discover-beacon.service'].replace('[Unit]\n',
        '[Unit]\nConflicts=host-discover.service host-discover-managed.service\nAfter=host-discover.service host-discover-managed.service\n', 1)
    # Keep both request processes alive until beacon finish during shutdown.
    # Accept=yes handlers cannot reliably be newly activated once stop jobs exist.
    for prefix, command in (('host-install-admission', 'state-admission-listen'),
                            ('host-discover-supervisor', 'serve-listen')):
        socket_name = prefix + '.socket'
        files[socket_name] = '\n'.join(line for line in files[socket_name].splitlines()
            if not line.startswith(('MaxConnections=', 'MaxConnectionsPerSource='))) + '\n'
        files[socket_name] = files[socket_name].replace('Accept=yes', 'Accept=no\nBacklog=8')
        service = files.pop(prefix + '@.service')
        service = '\n'.join(line for line in service.splitlines()
            if not line.startswith(('RuntimeMaxSec=', 'StandardInput='))) + '\n'
        service = service.replace('StandardOutput=socket', 'StandardOutput=journal')
        service = service.replace('state-admission-serve', command) if prefix == 'host-install-admission' else service.replace('supervisor serve', 'supervisor '+command)
        service = service.replace('[Service]\n', '[Service]\nSockets='+socket_name+'\n')
        files[prefix+'.service'] = service
    files['host-discover-beacon.service'] = files['host-discover-beacon.service'].replace('[Unit]\n',
        '[Unit]\nRequires=host-install-admission.service host-discover-supervisor.service\nAfter=host-install-admission.service host-discover-supervisor.service\n', 1)
    # SIGTERM must reach the beacon first: a cgroup-wide TERM can kill its
    # in-flight lsblk admission check before it can finish the protected run.
    # mixed retains cgroup-wide SIGKILL if graceful shutdown times out.
    files['host-discover-beacon.service'] = '\n'.join(
        line for line in files['host-discover-beacon.service'].splitlines()
        if not line.startswith(('KillMode=', 'TimeoutStopSec='))) + '\n'
    files['host-discover-beacon.service'] = files['host-discover-beacon.service'].replace(
        '[Service]\n', '[Service]\nKillMode=mixed\nTimeoutStopSec=90s\n', 1)
    files = {name: data.replace('/usr/bin/host-', executable_directory+'/host-').encode() for name,data in files.items()}
    manifest = canonical(dict(
        schema=1,
        kind='zog-managed-beacon-profile',
        consumer_template_commit=CONSUMER_COMMIT,
        consumer_version=CONSUMER_VERSION,
        consumer_runtime_modules=reviewed_modules,
        executable_directory=executable_directory,
        files={n:hashlib.sha256(d).hexdigest() for n,d in files.items()},
        disabled_profiles=['host-discover.service','host-discover-managed.service'],
        enable=['host-discover-beacon.service'], supervisor_preparation='explicit-only',
        certificate_assignment_authority_pin=(None if pin is None else {
            'path': '/etc/zog/host-install/' + AUTHORITY_PIN_NAME,
            'registry_id': pin['registry_id'], 'authority_key_id': pin['authority_key_id'],
            'sha256': hashlib.sha256(canonical(pin)).hexdigest()})))
    output = Path(output).absolute()
    parent = directory(str(output.parent))
    root = None
    try:
        root = ensure_directory(parent, output.name, 0, 0, 0o700)
        with lock(root):
            require(set(os.listdir(root)) <= {'.host-install.lock','profile.json','.pending.profile.json','etc','.pending-dir.etc'},
                    'profile-conflict', 'Unexpected overlay contents')
            # Intent is immutable; files resume only with identical bytes.
            publish(root, 'profile.json', manifest, 0o444)
            opened = []; current = root
            try:
                for name in ('etc','systemd','system'):
                    current = ensure_directory(current,name,0,0,0o755); opened.append(current)
                for name,data in files.items(): publish(current,name,data,0o444)
            finally:
                for fd in reversed(opened): os.close(fd)
            if pin is not None:
                opened = []; current = root
                try:
                    for name in ('etc','zog','host-install'):
                        current = ensure_directory(current,name,0,0,0o755); opened.append(current)
                    publish(current, AUTHORITY_PIN_NAME, canonical(pin), 0o444)
                finally:
                    for fd in reversed(opened): os.close(fd)
        return dict(status='beacon-profile-staged', output=str(output), services_enabled=False, state_modified=False,
                    certificate_assignment_authority_pin_installed=pin is not None,
                    certificate_assignment_authority_key_id=None if pin is None else pin['authority_key_id'])
    finally:
        if root is not None: os.close(root)
        os.close(parent)
