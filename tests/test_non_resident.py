import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from zog.host_install.non_resident import build_plan, validate_plan
from zog.host_install.state_contract import StateError, digest, host_slots, installation_mode, validate
from zog.host_install.state_inspect import assess_mount, directory, host_generation_report
from zog.host_install.state_provision import prepare_tree, transition

ROOT = Path(__file__).resolve().parents[1]
RESIDENT = json.loads((ROOT / 'examples/state-contract-v1/bundle.json').read_text())
NON_RESIDENT = json.loads((ROOT / 'examples/non-resident-state-v1/bundle.json').read_text())
PLAN = json.loads((ROOT / 'examples/non-resident-state-v1/disposable-host-plan.json').read_text())


class Crash(BaseException):
    pass


class Context:
    def __init__(self, root):
        self.root = Path(root)
        self.root.chmod(0o755)
        self.fd = directory(str(self.root))
        self.bundle = copy.deepcopy(NON_RESIDENT)

    def recheck(self):
        return None

    def close(self):
        os.close(self.fd)


class ContractTests(unittest.TestCase):
    def test_legacy_resident_and_schema2_non_resident_are_distinct(self):
        validate(RESIDENT)
        validate(NON_RESIDENT)
        self.assertEqual(installation_mode(RESIDENT['installation']), 'resident')
        self.assertEqual(installation_mode(NON_RESIDENT['installation']), 'non-resident')
        self.assertEqual(host_slots(NON_RESIDENT['installation']),
                         {'HOST-A': None, 'HOST-B': None})
        recorded = NON_RESIDENT['installation']['installer_recorded']
        for forbidden in ('expected_artifact_id', 'expected_host_generation',
                          'expected_slot', 'root_partuuid', 'host_slots',
                          'foreign_boot_bundle'):
            self.assertNotIn(forbidden, recorded)

    def test_unknown_schema_mode_and_resident_fields_fail_closed(self):
        variants = []
        b = copy.deepcopy(NON_RESIDENT)
        b['installation']['schema'] = 3
        variants.append(b)
        b = copy.deepcopy(NON_RESIDENT)
        b['installation']['installation_mode'] = 'container'
        variants.append(b)
        b = copy.deepcopy(NON_RESIDENT)
        b['installation']['installer_recorded']['expected_slot'] = 'HOST-A'
        variants.append(b)
        b = copy.deepcopy(NON_RESIDENT)
        b['installation']['security']['secure_boot'] = 'verified'
        variants.append(b)
        for item in variants:
            with self.subTest(item=item['installation']), self.assertRaises(StateError):
                validate(item)

    def test_fixed_accounts_reject_collision_in_both_modes(self):
        for source in (RESIDENT, NON_RESIDENT):
            b = copy.deepcopy(source)
            b['accounts']['users']['box-control']['uid'] = 970
            with self.subTest(mode=installation_mode(source['installation'])), self.assertRaises(StateError):
                validate(b)

    def test_non_resident_upgrade_preserves_mode_and_state(self):
        new = copy.deepcopy(NON_RESIDENT)
        new['installation']['operation'] = 'upgrade'
        new['installation']['record_id'] = '99999999-9999-4999-8999-999999999999'
        new['bootstrap']['configuration_revision'] = 2
        new['bootstrap']['mode'] = 'existing'
        new['bootstrap']['installation_record']['sha256'] = digest(new['installation'])
        transition(new, NON_RESIDENT)

        with self.assertRaisesRegex(StateError, 'installation mode'):
            transition(new, RESIDENT)


class PlanTests(unittest.TestCase):
    def test_machine_readable_plan_matches_committed_fixture(self):
        self.assertEqual(build_plan(NON_RESIDENT), PLAN)
        self.assertEqual(validate_plan(copy.deepcopy(PLAN)), PLAN)
        self.assertTrue(PLAN['removal']['retain_state_default'])
        self.assertFalse(PLAN['execution']['device_writes_authorized'])
        self.assertFalse(PLAN['systemd']['mount_unit']['host_os_boot_required'])

    def test_plan_never_becomes_format_or_identity_authority(self):
        for field in ('device_writes_authorized', 'formatting_authorized',
                      'identity_initialization_authorized'):
            plan = copy.deepcopy(PLAN)
            plan['execution'][field] = True
            with self.subTest(field=field), self.assertRaises(StateError):
                validate_plan(plan)

    def test_cli_projects_plan_without_writing(self):
        source = ROOT / 'examples/non-resident-state-v1/bundle.json'
        result = subprocess.run(
            [sys.executable, '-m', 'zog.host_install', 'non-resident-plan', str(source)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['result'], PLAN)


class StateReuseTests(unittest.TestCase):
    def test_non_resident_mount_rules_keep_root_exclusion_and_rw_requirement(self):
        expected = NON_RESIDENT['bootstrap']['state']
        row = {'id': '42', 'device': '8:3', 'root': '/', 'target': '/state',
               'options': ['rw'], 'type': 'ext4', 'super_options': ['rw']}
        device = {'maj:min': '8:3', 'type': 'part',
                  'partuuid': expected['partition_partuuid'],
                  'uuid': expected['filesystem_uuid'], 'fstype': 'ext4'}
        assess_mount([row], [device], expected, '8:1')
        with self.assertRaisesRegex(StateError, 'host-root-device'):
            assess_mount([row], [device], expected, '8:3')
        ro = copy.deepcopy(row)
        ro['super_options'] = ['ro']
        with self.assertRaisesRegex(StateError, 'state-read-only'):
            assess_mount([ro], [device], expected, '8:1')

    def test_interrupted_non_resident_state_preparation_reuses_same_volume(self):
        with tempfile.TemporaryDirectory() as temp:
            c = Context(temp)
            try:
                volume = c.bundle['bootstrap']['state']['state_volume_id']
                def checkpoint(point):
                    if point == 'linked:.zog-state.json':
                        raise Crash(point)
                with self.assertRaises(Crash):
                    prepare_tree(c, volume, checkpoint=checkpoint,
                                 service_ids=(0, 0, 0, 0))
                result = prepare_tree(c, volume, service_ids=(0, 0, 0, 0))
                self.assertEqual(result['status'], 'state-prepared')
                self.assertFalse(result['identity_created'])
            finally:
                c.close()

    def test_non_resident_host_report_does_not_invent_slot_or_boot_attestation(self):
        class C:
            bundle = NON_RESIDENT
            def recheck(self):
                return None
        report = host_generation_report(C())
        self.assertEqual(report['schema'], 2)
        self.assertEqual(report['installation']['installation_mode'], 'non-resident')
        self.assertIsNone(report['selected_slot'])
        self.assertIsNone(report['booted_slot'])
        self.assertEqual(report['slots'], {'HOST-A': None, 'HOST-B': None})
        self.assertEqual(report['host_os']['boot'], 'externally-managed')


if __name__ == '__main__':
    unittest.main()
