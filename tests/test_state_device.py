import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


def inventory():
    def row(path, devno, kind, *, identity=None, parents=None, mounts=None,
            partuuid=None, uuid=None, fstype=None, pttype=None):
        return {
            'path': path,
            'devno': devno,
            'type': kind,
            'size': 1024 * 1024 * 1024,
            'read_only': False,
            'identity': identity,
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
    return build_plan(BUNDLE, inventory(), [], 'serial:vol-state', 'vol-state')


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
        self.assertEqual(value['selected_volume_reference'], 'vol-state')
        self.assertFalse(value['authority']['formatting_authorized'])
        self.assertEqual(
            value['state']['partition_partuuid'],
            BUNDLE['bootstrap']['state']['partition_partuuid'])
        self.assertNotEqual(value['target_identity'], value['target_observation']['path'])

    def test_root_target_existing_partition_and_signature_are_rejected(self):
        with self.assertRaises(Exception):
            build_plan(BUNDLE, inventory(), [], 'serial:root', 'root-volume')

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
            build_plan(BUNDLE, snap, [], 'serial:vol-state', 'vol-state')

        with self.assertRaisesRegex(StateError, 'target-signatures'):
            build_plan(
                BUNDLE, inventory(),
                [{'offset': '0x438', 'type': 'ext4', 'uuid': 'old', 'label': None}],
                'serial:vol-state', 'vol-state')

    def test_plan_is_bound_to_exact_bundle(self):
        value = plan()
        changed = copy.deepcopy(BUNDLE)
        changed['bootstrap']['configuration_revision'] = 2
        with self.assertRaisesRegex(StateError, 'plan-binding'):
            validate_plan(value, changed)


class ApplyTests(unittest.TestCase):
    def test_apply_requires_explicit_matching_fresh_volume_id(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(StateError, 'format-authorization'):
                apply_live(BUNDLE, plan(), Path(temp) / 'operation', 'wrong-volume')

    def test_fresh_apply_advances_once_and_never_authorizes_identity(self):
        value = plan()
        with tempfile.TemporaryDirectory() as temp, \
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
            with patch('zog.host_install.state_device.collect_inventory',
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
            substituted['selected_volume_reference'] = 'different-volume'
            with self.assertRaisesRegex(StateError, 'operation binding'):
                with patch('zog.host_install.state_device.collect_inventory'):
                    apply_live(
                        BUNDLE, substituted, operation_path,
                        substituted['state']['state_volume_id'])


if __name__ == '__main__':
    unittest.main()
