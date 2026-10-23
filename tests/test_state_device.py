import copy
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from zog.host_install import state_device
from zog.host_install.state_contract import StateError, digest
from zog.host_install.state_device import (
    _new_operation,
    _operation_directory,
    _write_operation,
    apply_live,
    build_plan,
    validate_plan,
)

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = json.loads((ROOT / 'examples/non-resident-state-v1/bundle.json').read_text())


@contextmanager
def no_host_lock():
    yield


def inventory():
    def row(path, devno, kind, *, identity=None, identities=None,
            parents=None, mounts=None, partuuid=None, uuid=None,
            fstype=None, pttype=None):
        return {
            'path': path,
            'devno': devno,
            'type': kind,
            'size': 1024 * 1024 * 1024,
            'read_only': False,
            'identity': identity,
            **({'identities': identities} if identities is not None else {}),
            'parents': parents or [],
            'mounts': mounts or [],
            'holders': [],
            'partuuid': partuuid,
            'uuid': uuid,
            'fstype': fstype,
            'pttype': pttype,
        }
    return {
        'schema': 1,
        'complete': True,
        'root_devnos': ['253:0'],
        'devices': [
            row('/dev/rootdisk', '8:0', 'disk', identity='serial:root'),
            row('/dev/rootpart', '8:1', 'part', parents=['/dev/rootdisk']),
            row('/dev/mapper/root', '253:0', 'lvm',
                parents=['/dev/rootpart'], mounts=['/']),
            row('/dev/state-disk', '8:16', 'disk', identity='serial:vol-state'),
        ],
    }


def plan():
    return build_plan(BUNDLE, inventory(), [], 'serial:vol-state', 'identity:serial:vol-state')


def partitioned():
    snap = inventory()
    disk = next(row for row in snap['devices'] if row['path'] == '/dev/state-disk')
    disk['pttype'] = 'gpt'
    snap['devices'].append({
        'path': '/dev/state-part',
        'devno': '8:17',
        'type': 'part',
        'size': 1024 * 1024 * 1000,
        'read_only': False,
        'identity': None,
        'parents': ['/dev/state-disk'],
        'mounts': [],
        'holders': [],
        'partuuid': BUNDLE['bootstrap']['state']['partition_partuuid'],
        'uuid': None,
        'fstype': None,
        'pttype': None,
    })
    return snap


def formatted():
    snap = partitioned()
    part = next(row for row in snap['devices'] if row['path'] == '/dev/state-part')
    part['uuid'] = BUNDLE['bootstrap']['state']['filesystem_uuid']
    part['fstype'] = 'ext4'
    return snap


class PlanTests(unittest.TestCase):
    def test_fresh_plan_binds_stable_identity_and_not_authority(self):
        value = plan()
        self.assertEqual(validate_plan(copy.deepcopy(value), BUNDLE), value)
        self.assertEqual(value['target_identity'], 'serial:vol-state')
        self.assertEqual(value['selected_volume_reference'], 'identity:serial:vol-state')
        self.assertEqual(value['volume_binding_method'], 'exact-stable-identity-v1')
        self.assertEqual(value['provider_identity'], 'serial:vol-state')
        self.assertEqual(
            value['target_observation']['identities'], ['serial:vol-state'])
        self.assertFalse(value['authority']['formatting_authorized'])
        self.assertEqual(
            value['state']['partition_partuuid'],
            BUNDLE['bootstrap']['state']['partition_partuuid'])
        self.assertNotEqual(value['target_identity'], value['target_observation']['path'])

    def test_root_target_existing_partition_and_signature_are_rejected(self):
        with self.assertRaises(Exception):
            build_plan(BUNDLE, inventory(), [], 'serial:root', 'identity:serial:root')

        snap = inventory()
        snap['devices'].append({
            'path': '/dev/state-part',
            'devno': '8:17',
            'type': 'part',
            'size': 512 * 1024 * 1024,
            'read_only': False,
            'identity': None,
            'parents': ['/dev/state-disk'],
            'mounts': [],
            'holders': [],
            'partuuid': None,
            'uuid': None,
            'fstype': None,
            'pttype': None,
        })
        with self.assertRaisesRegex(StateError, 'target-not-fresh'):
            build_plan(BUNDLE, snap, [], 'serial:vol-state', 'identity:serial:vol-state')

        with self.assertRaisesRegex(StateError, 'target-signatures'):
            build_plan(
                BUNDLE, inventory(),
                [{'offset': '0x438', 'type': 'ext4', 'uuid': 'old', 'label': None}],
                'serial:vol-state', 'identity:serial:vol-state')

    def test_aws_ebs_serial_and_wwn_aliases_resolve_one_whole_disk(self):
        snap = inventory()
        target = next(row for row in snap['devices'] if row['path'] == '/dev/state-disk')
        target['identity'] = 'wwn:nvme.1d0f-state'
        target['identities'] = [
            'wwn:nvme.1d0f-state',
            'serial:vol0123456789abcdef0',
        ]
        value = build_plan(
            BUNDLE, snap, [], 'wwn:nvme.1d0f-state',
            'aws-ebs:vol-0123456789abcdef0')
        self.assertEqual(value['volume_binding_method'], 'aws-ebs-nvme-serial-v1')
        self.assertEqual(value['provider_identity'], 'serial:vol0123456789abcdef0')
        self.assertEqual(
            value['target_observation']['identities'],
            ['serial:vol0123456789abcdef0', 'wwn:nvme.1d0f-state'])

        # The caller may also select the provider serial alias directly even when
        # WWN remains the inventory's primary identity.
        serial = build_plan(
            BUNDLE, snap, [], 'serial:vol0123456789abcdef0',
            'aws-ebs:vol-0123456789abcdef0')
        self.assertEqual(serial['provider_identity'], 'serial:vol0123456789abcdef0')

    def test_aws_ebs_alias_mismatch_missing_and_duplicate_whole_disks_fail(self):
        snap = inventory()
        target = next(row for row in snap['devices'] if row['path'] == '/dev/state-disk')
        target['identity'] = 'wwn:nvme.1d0f-state'
        target['identities'] = [
            'wwn:nvme.1d0f-state',
            'serial:vol0123456789abcdef0',
        ]
        with self.assertRaisesRegex(StateError, 'exactly one whole disk'):
            build_plan(
                BUNDLE, snap, [], 'wwn:nvme.1d0f-state',
                'aws-ebs:vol-fffffffffffffffff')

        missing = copy.deepcopy(snap)
        missing_target = next(
            row for row in missing['devices'] if row['path'] == '/dev/state-disk')
        missing_target['identities'] = ['wwn:nvme.1d0f-state']
        with self.assertRaisesRegex(StateError, 'exactly one whole disk'):
            build_plan(
                BUNDLE, missing, [], 'wwn:nvme.1d0f-state',
                'aws-ebs:vol-0123456789abcdef0')

        duplicate = copy.deepcopy(snap)
        other = copy.deepcopy(target)
        other['path'] = '/dev/other-state-disk'
        other['devno'] = '8:32'
        duplicate['devices'].append(other)
        with self.assertRaisesRegex(StateError, 'exactly one whole disk'):
            build_plan(
                BUNDLE, duplicate, [], 'wwn:nvme.1d0f-state',
                'aws-ebs:vol-0123456789abcdef0')

    def test_serial_only_device_still_resolves(self):
        snap = inventory()
        target = next(row for row in snap['devices'] if row['path'] == '/dev/state-disk')
        target['identity'] = 'serial:vol0123456789abcdef0'
        target['identities'] = ['serial:vol0123456789abcdef0']
        value = build_plan(
            BUNDLE, snap, [], 'serial:vol0123456789abcdef0',
            'aws-ebs:vol-0123456789abcdef0')
        self.assertEqual(
            value['target_observation']['identities'],
            ['serial:vol0123456789abcdef0'])

    def test_child_partition_inherited_wwn_does_not_ambiguate_retry(self):
        snap = partitioned()
        disk = next(row for row in snap['devices'] if row['path'] == '/dev/state-disk')
        disk['identity'] = 'wwn:nvme.1d0f-state'
        disk['identities'] = [
            'wwn:nvme.1d0f-state',
            'serial:vol0123456789abcdef0',
        ]
        part = next(row for row in snap['devices'] if row['path'] == '/dev/state-part')
        part['identity'] = 'wwn:nvme.1d0f-state'
        part['identities'] = [
            'wwn:nvme.1d0f-state',
            'serial:vol0123456789abcdef0',
        ]
        pristine = inventory()
        pristine_disk = next(
            row for row in pristine['devices'] if row['path'] == '/dev/state-disk')
        pristine_disk['identity'] = 'wwn:nvme.1d0f-state'
        pristine_disk['identities'] = list(disk['identities'])
        value = build_plan(
            BUNDLE, pristine, [], 'wwn:nvme.1d0f-state',
            'aws-ebs:vol-0123456789abcdef0')
        with patch('zog.host_install.state_device.signatures', return_value=[]):
            observed, resolved, resolved_part = state_device._device_state(value, snap)
        self.assertEqual(observed, 'partitioned')
        self.assertEqual(resolved['path'], '/dev/state-disk')
        self.assertEqual(resolved_part['path'], '/dev/state-part')

    def test_aws_provider_binding_cannot_select_running_root(self):
        snap = inventory()
        root = next(row for row in snap['devices'] if row['path'] == '/dev/rootdisk')
        root['identity'] = 'wwn:nvme.root'
        root['identities'] = [
            'wwn:nvme.root',
            'serial:vol0123456789abcdef0',
        ]
        with self.assertRaisesRegex(Exception, 'running root'):
            build_plan(
                BUNDLE, snap, [], 'wwn:nvme.root',
                'aws-ebs:vol-0123456789abcdef0')

    def test_plan_is_bound_to_exact_bundle(self):
        value = plan()
        changed = copy.deepcopy(BUNDLE)
        changed['bootstrap']['configuration_revision'] = 2
        with self.assertRaisesRegex(StateError, 'plan-binding'):
            validate_plan(value, changed)


class ApplyTests(unittest.TestCase):
    def test_apply_requires_explicit_matching_fresh_volume_id(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch('zog.host_install.state_device._host_transaction_lock',
                   no_host_lock):
            with self.assertRaisesRegex(StateError, 'format-authorization'):
                apply_live(BUNDLE, plan(), Path(temp) / 'operation', 'wrong-volume')

    def test_fresh_apply_advances_once_and_never_authorizes_identity(self):
        value = plan()
        with tempfile.TemporaryDirectory() as temp, \
             patch('zog.host_install.state_device._host_transaction_lock',
                   no_host_lock), \
             patch('zog.host_install.state_device.collect_inventory',
                   side_effect=[inventory(), partitioned(), formatted()]), \
             patch('zog.host_install.state_device._device_state',
                   side_effect=[
                       ('pristine', inventory()['devices'][-1], None),
                       ('partitioned', partitioned()['devices'][-2],
                        partitioned()['devices'][-1]),
                       ('formatted', formatted()['devices'][-2],
                        formatted()['devices'][-1]),
                   ]), \
             patch('zog.host_install.state_device._partition') as do_partition, \
             patch('zog.host_install.state_device._format') as do_format, \
             patch('zog.host_install.state_device._install_mount_unit'), \
             patch('zog.host_install.state_device.ensure_accounts'), \
             patch('zog.host_install.state_device.publish_configuration'), \
             patch('zog.host_install.state_device.prepare_live'):
            result = apply_live(
                BUNDLE, value, Path(temp) / 'operation',
                value['state']['state_volume_id'])
            self.assertEqual(result['phase'], 'prepared')
            self.assertFalse(result['identity_created'])
            self.assertFalse(result['identity_authorized'])
            self.assertFalse(result['host_os_boot_owned'])
            do_partition.assert_called_once()
            do_format.assert_called_once()

    def test_partitioned_resume_does_not_partition_again(self):
        value = plan()
        with tempfile.TemporaryDirectory() as temp:
            operation_path = Path(temp) / 'operation'
            path, fd = _operation_directory(operation_path)
            try:
                operation = _new_operation(value)
                operation['phase'] = 'planned'
                _write_operation(fd, operation)
            finally:
                import os
                os.close(fd)

            part_snap = partitioned()
            fmt_snap = formatted()
            with patch('zog.host_install.state_device._host_transaction_lock',
                       no_host_lock), \
                 patch('zog.host_install.state_device.collect_inventory',
                       side_effect=[part_snap, fmt_snap]), \
                 patch('zog.host_install.state_device._device_state',
                       side_effect=[
                           ('partitioned', part_snap['devices'][-2],
                            part_snap['devices'][-1]),
                           ('formatted', fmt_snap['devices'][-2],
                            fmt_snap['devices'][-1]),
                       ]), \
                 patch('zog.host_install.state_device._partition') as do_partition, \
                 patch('zog.host_install.state_device._format') as do_format, \
                 patch('zog.host_install.state_device._install_mount_unit'), \
                 patch('zog.host_install.state_device.ensure_accounts'), \
                 patch('zog.host_install.state_device.publish_configuration'), \
                 patch('zog.host_install.state_device.prepare_live'):
                result = apply_live(
                    BUNDLE, value, operation_path,
                    value['state']['state_volume_id'])
                self.assertEqual(result['phase'], 'prepared')
                do_partition.assert_not_called()
                do_format.assert_called_once()

    def test_complete_apply_transaction_is_serialized_before_device_observation(self):
        value = plan()
        locked = {'value': False}
        events = []
        observed = iter([
            ('pristine', inventory()['devices'][-1], None),
            ('partitioned', partitioned()['devices'][-2],
             partitioned()['devices'][-1]),
            ('formatted', formatted()['devices'][-2],
             formatted()['devices'][-1]),
        ])
        snapshots = iter([inventory(), partitioned(), formatted()])
        original_load = state_device._load_operation

        @contextmanager
        def host_lock():
            self.assertFalse(locked['value'])
            locked['value'] = True
            events.append('host-lock-enter')
            try:
                yield
            finally:
                events.append('host-lock-exit')
                locked['value'] = False

        @contextmanager
        def operation_lock(fd, name):
            self.assertEqual(name, '.state-device.lock')
            self.assertTrue(locked['value'])
            events.append('operation-lock-enter')
            try:
                yield
            finally:
                events.append('operation-lock-exit')

        def must_be_locked(label, result=None):
            self.assertTrue(locked['value'], label)
            events.append(label)
            return result

        def checked_load(fd):
            must_be_locked('load-operation')
            return original_load(fd)

        def checked_inventory():
            return must_be_locked('collect-inventory', next(snapshots))

        def checked_device_state(plan_value, snapshot):
            return must_be_locked('device-state', next(observed))

        with tempfile.TemporaryDirectory() as temp, \
             patch('zog.host_install.state_device._host_transaction_lock',
                   host_lock), \
             patch('zog.host_install.state_device.lock', operation_lock), \
             patch('zog.host_install.state_device._load_operation',
                   side_effect=checked_load), \
             patch('zog.host_install.state_device.collect_inventory',
                   side_effect=checked_inventory), \
             patch('zog.host_install.state_device._device_state',
                   side_effect=checked_device_state), \
             patch('zog.host_install.state_device._partition',
                   side_effect=lambda *a: must_be_locked('partition')), \
             patch('zog.host_install.state_device._format',
                   side_effect=lambda *a: must_be_locked('format')), \
             patch('zog.host_install.state_device._install_mount_unit',
                   side_effect=lambda *a: must_be_locked('mount')), \
             patch('zog.host_install.state_device.ensure_accounts',
                   side_effect=lambda *a: must_be_locked('accounts')), \
             patch('zog.host_install.state_device.publish_configuration',
                   side_effect=lambda *a, **k: must_be_locked('configuration')), \
             patch('zog.host_install.state_device.prepare_live',
                   side_effect=lambda *a: must_be_locked('prepare')):
            result = apply_live(
                BUNDLE, value, Path(temp) / 'operation',
                value['state']['state_volume_id'])

        self.assertEqual(result['phase'], 'prepared')
        self.assertEqual(events[0], 'host-lock-enter')
        self.assertEqual(events[-1], 'host-lock-exit')
        self.assertIn('operation-lock-enter', events)
        self.assertIn('operation-lock-exit', events)
        for label in (
                'load-operation', 'collect-inventory', 'device-state',
                'partition', 'format', 'mount', 'accounts',
                'configuration', 'prepare'):
            self.assertIn(label, events)
        self.assertLess(
            events.index('host-lock-enter'), events.index('operation-lock-enter'))
        self.assertLess(
            events.index('operation-lock-enter'), events.index('collect-inventory'))
        self.assertLess(
            events.index('prepare'), events.index('operation-lock-exit'))
        self.assertLess(
            events.index('operation-lock-exit'), events.index('host-lock-exit'))

    def test_post_lock_revalidation_rejects_changed_target_before_partition(self):
        value = plan()
        changed = inventory()
        target = next(
            row for row in changed['devices']
            if row['identity'] == value['target_identity'])
        target['size'] += 4096
        locked = {'value': False}

        @contextmanager
        def host_lock():
            locked['value'] = True
            try:
                yield
            finally:
                locked['value'] = False

        @contextmanager
        def operation_lock(fd, name):
            self.assertEqual(name, '.state-device.lock')
            self.assertTrue(locked['value'])
            yield

        def checked_inventory():
            self.assertTrue(locked['value'])
            return changed

        with tempfile.TemporaryDirectory() as temp, \
             patch('zog.host_install.state_device._host_transaction_lock',
                   host_lock), \
             patch('zog.host_install.state_device.lock', operation_lock), \
             patch('zog.host_install.state_device.collect_inventory',
                   side_effect=checked_inventory), \
             patch('zog.host_install.state_device._partition') as do_partition:
            with self.assertRaisesRegex(StateError, 'different-sized device'):
                apply_live(
                    BUNDLE, value, Path(temp) / 'operation',
                    value['state']['state_volume_id'])
            do_partition.assert_not_called()

    def test_saved_plan_digest_prevents_plan_substitution(self):
        value = plan()
        with tempfile.TemporaryDirectory() as temp:
            operation_path = Path(temp) / 'operation'
            _, fd = _operation_directory(operation_path)
            try:
                _write_operation(fd, _new_operation(value))
            finally:
                import os
                os.close(fd)
            substituted = copy.deepcopy(value)
            substituted['target_identity'] = 'serial:different-volume'
            substituted['provider_identity'] = 'serial:different-volume'
            substituted['selected_volume_reference'] = 'identity:serial:different-volume'
            substituted['target_observation']['identities'] = [
                'serial:different-volume']
            with self.assertRaisesRegex(StateError, 'operation binding'):
                with patch('zog.host_install.state_device._host_transaction_lock',
                           no_host_lock), \
                     patch('zog.host_install.state_device.collect_inventory'):
                    apply_live(
                        BUNDLE, substituted, operation_path,
                        substituted['state']['state_volume_id'])


if __name__ == '__main__':
    unittest.main()
