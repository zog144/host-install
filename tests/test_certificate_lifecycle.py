import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from zog.host_install.certificate_lifecycle import (
    load_record,
    reconcile,
    store_record,
)
from zog.host_install.cli import main
from zog.host_install.state_contract import StateError


def observation(
    *,
    event="install",
    application="available",
    generation="host-generation-1",
    policy="approved",
    persistent="available",
    state_id="certificate-state-1",
    preparation_revision="certify-manage-state-v1",
    preparation="not-run",
    identity=False,
    lineage="absent",
    issuance="not-started",
    local_verified=False,
    publication="not-started",
    external="not-verified",
):
    if application != "available":
        state_id = None
        preparation_revision = None
    elif persistent != "available":
        state_id = None
    approved = policy == "approved"
    return {
        "schema": 1,
        "kind": "zog-certificate-lifecycle-observation",
        "event": event,
        "application": {
            "status": application,
            "persistent_state_id": state_id,
            "preparation_revision": preparation_revision,
        },
        "evidence": {
            "schema": 1,
            "kind": "zog-certificate-enablement-evidence",
            "state": {"verified": True, "recovery_hold": False},
            "grant": {"status": "verified", "grant_id": "grant-17"},
            "software": {"status": "verified", "generation": generation},
            "policy": {
                "status": policy,
                "hostname_approved": approved,
                "challenge_approved": approved,
                "challenge": "dns-01" if approved else None,
            },
            "persistent": {
                "status": persistent,
                "existing_acme_identity": identity,
                "lineage_status": lineage,
                "replacement_attempted": False,
            },
            "preparation": {"status": preparation},
            "issuance": {
                "status": issuance,
                "local_verified": local_verified,
            },
            "publication": {"status": publication},
            "external": {"status": external},
        },
    }


def active(**changes):
    values = dict(
        preparation="complete",
        identity=True,
        lineage="healthy",
        issuance="issued",
        local_verified=True,
        publication="loaded",
        external="verified",
    )
    values.update(changes)
    return observation(**values)


class CertificateLifecycleTests(unittest.TestCase):
    def test_install_waits_for_configuration_and_application_then_prepares_once(self):
        first = reconcile(
            None,
            observation(application="unavailable", policy="missing", persistent="unavailable"),
        )
        self.assertEqual(
            first["status"]["code"],
            "awaiting-operator-approved-hostname-challenge",
        )
        self.assertTrue(first["status"]["configuration_pending"])
        self.assertFalse(first["status"]["application_available"])
        self.assertIsNone(first["record"]["persistent_state_id"])
        self.assertIsNone(first["record"]["prepared_revision"])

        second = reconcile(first["record"], observation(policy="missing"))
        self.assertEqual(
            second["status"]["code"],
            "awaiting-operator-approved-hostname-challenge",
        )
        self.assertEqual(
            second["record"]["persistent_state_id"],
            "certificate-state-1",
        )

        third = reconcile(second["record"], observation())
        self.assertEqual(third["status"]["code"], "application-preparation-required")
        self.assertFalse(third["status"]["durable_preparation_complete"])

        fourth = reconcile(
            third["record"],
            observation(application="unavailable", persistent="unavailable"),
        )
        self.assertEqual(
            fourth["status"]["code"],
            "certificate-application-unavailable",
        )
        self.assertEqual(
            fourth["record"]["persistent_state_id"],
            "certificate-state-1",
        )
        self.assertFalse(fourth["status"]["issuance_allowed"])

        fifth = reconcile(
            fourth["record"],
            observation(preparation="complete"),
        )
        self.assertEqual(fifth["status"]["code"], "ready-for-authorized-issuance")
        self.assertTrue(fifth["status"]["issuance_allowed"])
        self.assertEqual(
            fifth["record"]["prepared_revision"],
            "certify-manage-state-v1",
        )
        self.assertEqual(fifth["record"]["revision"], 5)

    def test_acme_account_can_exist_before_first_certificate(self):
        result = reconcile(
            None,
            observation(
                preparation="complete",
                identity=True,
                lineage="absent",
            ),
        )
        self.assertTrue(result["record"]["acme_identity_seen"])
        self.assertFalse(result["record"]["lineage_seen"])
        self.assertEqual(result["status"]["identity_action"], "preserve-existing")
        self.assertEqual(result["status"]["code"], "ready-for-authorized-issuance")

        reboot = reconcile(
            result["record"],
            observation(
                event="reboot",
                application="unavailable",
                persistent="unavailable",
                preparation="complete",
                identity=True,
                lineage="absent",
            ),
        )
        self.assertTrue(reboot["record"]["acme_identity_seen"])
        self.assertEqual(reboot["status"]["identity_action"], "preserve-existing")

        recovered = reconcile(
            reboot["record"],
            observation(
                event="status",
                preparation="complete",
                identity=True,
                lineage="absent",
            ),
        )
        self.assertEqual(recovered["status"]["code"], "ready-for-authorized-issuance")
        self.assertEqual(
            recovered["record"]["prepared_revision"],
            "certify-manage-state-v1",
        )

    def test_reboot_and_upgrade_preserve_durable_identity_and_preparation(self):
        installed = reconcile(None, active())
        self.assertEqual(installed["status"]["code"], "external-https-ready")
        self.assertTrue(installed["record"]["acme_identity_seen"])
        self.assertTrue(installed["record"]["lineage_seen"])
        self.assertEqual(
            installed["record"]["prepared_revision"],
            "certify-manage-state-v1",
        )

        reboot = reconcile(
            installed["record"],
            active(
                event="reboot",
                application="unavailable",
                persistent="unavailable",
            ),
        )
        self.assertEqual(reboot["status"]["code"], "persistent-state-unavailable")
        self.assertFalse(reboot["status"]["application_available"])
        self.assertTrue(reboot["status"]["external_https_observed"])
        self.assertTrue(reboot["record"]["acme_identity_seen"])
        self.assertTrue(reboot["record"]["lineage_seen"])
        self.assertEqual(
            reboot["record"]["prepared_revision"],
            "certify-manage-state-v1",
        )

        returned = reconcile(reboot["record"], active(event="status"))
        self.assertEqual(returned["status"]["code"], "external-https-ready")
        self.assertFalse(returned["status"]["generation_changed"])

        upgraded = reconcile(
            returned["record"],
            active(event="upgrade", generation="host-generation-2"),
        )
        self.assertEqual(upgraded["status"]["code"], "external-https-ready")
        self.assertTrue(upgraded["status"]["generation_changed"])
        self.assertEqual(
            upgraded["record"]["first_software_generation"],
            "host-generation-1",
        )
        self.assertEqual(
            upgraded["record"]["last_software_generation"],
            "host-generation-2",
        )
        self.assertEqual(
            upgraded["record"]["prepared_revision"],
            "certify-manage-state-v1",
        )
        self.assertEqual(upgraded["status"]["identity_action"], "preserve-existing")

    def test_persistent_state_replacement_is_not_adopted(self):
        installed = reconcile(None, active())
        replaced = active()
        replaced["application"]["persistent_state_id"] = "certificate-state-2"
        result = reconcile(installed["record"], replaced)
        self.assertEqual(
            result["status"]["code"],
            "certificate-persistent-state-replaced",
        )
        self.assertFalse(result["status"]["issuance_allowed"])
        self.assertEqual(
            result["record"]["persistent_state_id"],
            "certificate-state-1",
        )

    def test_preparation_revision_change_requires_explicit_migration(self):
        installed = reconcile(None, active())
        changed = active(event="upgrade", generation="host-generation-2")
        changed["application"]["preparation_revision"] = "certify-manage-state-v2"
        result = reconcile(installed["record"], changed)
        self.assertEqual(
            result["status"]["code"],
            "certificate-preparation-migration-required",
        )
        self.assertEqual(
            result["record"]["prepared_revision"],
            "certify-manage-state-v1",
        )
        self.assertFalse(result["status"]["issuance_allowed"])

    def test_durable_identity_or_lineage_disappearance_blocks(self):
        installed = reconcile(None, active())

        missing_identity = active()
        missing_identity["evidence"]["persistent"]["existing_acme_identity"] = False
        result = reconcile(installed["record"], missing_identity)
        self.assertEqual(result["status"]["code"], "acme-identity-disappeared")

        missing_lineage = active()
        missing_lineage["evidence"]["persistent"]["lineage_status"] = "absent"
        result = reconcile(installed["record"], missing_lineage)
        self.assertEqual(result["status"]["code"], "certificate-lineage-disappeared")

    def test_policy_revocation_conflict_and_migration_are_hard_blocks(self):
        for status in ("revoked", "conflict", "migration-required"):
            result = reconcile(None, observation(policy=status))
            with self.subTest(status=status):
                self.assertEqual(
                    result["status"]["code"],
                    "certificate-policy-" + status,
                )
                self.assertFalse(result["status"]["configuration_pending"])
                self.assertFalse(result["status"]["issuance_allowed"])
                self.assertFalse(result["status"]["proxy_exposure_allowed"])
                self.assertFalse(result["status"]["archive_role_change_allowed"])

    def test_atomic_record_round_trip_and_stale_writer_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "certificate-lifecycle.json")
            first = reconcile(None, observation(policy="missing"))
            store_record(path, first["record"], None)
            loaded = load_record(path)
            self.assertEqual(loaded, first["record"])

            second = reconcile(loaded, observation(preparation="complete"))
            store_record(path, second["record"], loaded)
            self.assertEqual(load_record(path), second["record"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            with self.assertRaisesRegex(StateError, "record changed since load"):
                store_record(path, first["record"], None)

    def test_simulation_cli_persists_only_secret_free_lifecycle_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = root / "lifecycle.json"
            obs = root / "observation.json"
            obs.write_text(json.dumps(observation(policy="missing")))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main([
                        "certificate-lifecycle-simulate",
                        str(obs),
                        "--record",
                        str(record),
                    ]),
                    0,
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(
                payload["result"]["status"]["code"],
                "awaiting-operator-approved-hostname-challenge",
            )
            stored = json.dumps(load_record(record), sort_keys=True)
            for forbidden in (
                "station.example",
                "acme_directory",
                "dns_plugin",
                "credential_id",
                "privkey",
                "fullchain",
            ):
                self.assertNotIn(forbidden, stored)


if __name__ == "__main__":
    unittest.main()
