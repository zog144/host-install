import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from zog.host_install.certificate_gate import decide, validate_evidence
from zog.host_install.cli import main
from zog.host_install.state_contract import StateError


def evidence():
    return {
        "schema": 1,
        "kind": "zog-certificate-enablement-evidence",
        "state": {"verified": True, "recovery_hold": False},
        "grant": {"status": "verified", "grant_id": "grant-17"},
        "software": {"status": "verified", "generation": "host-generation-42"},
        "policy": {
            "status": "approved",
            "hostname_approved": True,
            "challenge_approved": True,
            "challenge": "http-01",
        },
        "persistent": {
            "status": "available",
            "existing_acme_identity": False,
            "lineage_status": "absent",
            "replacement_attempted": False,
        },
        "preparation": {"status": "complete"},
        "issuance": {"status": "not-started", "local_verified": False},
        "publication": {"status": "not-started"},
        "external": {"status": "not-verified"},
    }


UNSAFE_FALSE = (
    "self_signed_allowed",
    "public_auto_issuance_allowed",
    "proxy_exposure_allowed",
    "archive_role_change_allowed",
)


class CertificateGateTests(unittest.TestCase):
    def assert_fail_closed(self, result):
        for field in UNSAFE_FALSE:
            self.assertIs(result[field], False, field)
        self.assertIs(result["station_observer_mtls_separate"], True)

    def test_dependency_order_reaches_authorized_issuance_only_after_prerequisites(self):
        e = evidence()
        r = decide(e)
        self.assertEqual(r["code"], "ready-for-authorized-issuance")
        self.assertTrue(r["issuance_allowed"])
        self.assertFalse(r["host_deploy_handoff_ready"])
        self.assertFalse(r["external_https_ready"])
        self.assertEqual(r["identity_action"], "create-only-on-authorized-issuance")
        self.assert_fail_closed(r)

        checks = [
            (("state", "verified"), False, "state-unverified"),
            (("grant", "status"), "missing", "application-grant-missing"),
            (("software", "status"), "missing", "software-generation-missing"),
            (("persistent", "status"), "unavailable", "persistent-state-unavailable"),
            (("preparation", "status"), "not-run", "application-preparation-required"),
        ]
        for (section, field), value, code in checks:
            candidate = evidence()
            candidate[section][field] = value
            if section == "software":
                candidate[section]["generation"] = None
            if section == "grant":
                candidate[section]["grant_id"] = None
            result = decide(candidate)
            with self.subTest(section=section, field=field):
                self.assertEqual(result["code"], code)
                self.assertFalse(result["issuance_allowed"])
                self.assertFalse(result["external_https_ready"])
                self.assert_fail_closed(result)

    def test_missing_policy_never_guesses_or_auto_issues(self):
        e = evidence()
        e["policy"] = {
            "status": "missing",
            "hostname_approved": False,
            "challenge_approved": False,
            "challenge": None,
        }
        r = decide(e)
        self.assertEqual(r["status"], "awaiting-operator")
        self.assertEqual(r["code"], "awaiting-operator-approved-hostname-challenge")
        self.assertEqual(r["next_step"], "approve-hostname-and-challenge")
        self.assertFalse(r["issuance_allowed"])
        self.assert_fail_closed(r)

    def test_existing_acme_identity_is_preserved_across_generation_change(self):
        for generation in ("host-generation-42", "host-generation-43"):
            e = evidence()
            e["software"]["generation"] = generation
            e["persistent"].update(
                existing_acme_identity=True,
                lineage_status="healthy",
            )
            r = decide(e)
            with self.subTest(generation=generation):
                self.assertEqual(r["identity_action"], "preserve-existing")
                self.assertEqual(r["code"], "ready-for-authorized-issuance")
                self.assert_fail_closed(r)

        e["persistent"]["replacement_attempted"] = True
        r = decide(e)
        self.assertEqual(r["code"], "acme-identity-regeneration-forbidden")
        self.assertFalse(r["issuance_allowed"])
        self.assert_fail_closed(r)

    def test_failure_and_uncertainty_never_enable_fallback(self):
        mutations = [
            ("preparation", "status", "failed", "application-preparation-failed"),
            ("issuance", "status", "failed", "certificate-issuance-failed"),
            ("issuance", "status", "uncertain", "certificate-issuance-uncertain"),
            ("persistent", "lineage_status", "uncertain", "certificate-lineage-uncertain"),
        ]
        for section, field, value, code in mutations:
            e = evidence()
            e[section][field] = value
            result = decide(e)
            with self.subTest(code=code):
                self.assertEqual(result["code"], code)
                self.assertFalse(result["issuance_allowed"])
                self.assertFalse(result["host_deploy_handoff_ready"])
                self.assertFalse(result["external_https_ready"])
                self.assert_fail_closed(result)

    def test_local_certificate_is_not_external_https_readiness(self):
        e = evidence()
        e["issuance"] = {"status": "issued", "local_verified": True}
        for publication in ("not-started", "issuer-staged", "delivered"):
            e["publication"]["status"] = publication
            r = decide(e)
            with self.subTest(publication=publication):
                self.assertEqual(r["code"], "host-deploy-publication-required")
                self.assertTrue(r["host_deploy_handoff_ready"])
                self.assertFalse(r["external_https_ready"])
                self.assert_fail_closed(r)

        e["publication"]["status"] = "loaded"
        r = decide(e)
        self.assertEqual(r["code"], "external-https-verification-required")
        self.assertFalse(r["external_https_ready"])
        self.assert_fail_closed(r)

        e["external"]["status"] = "verified"
        r = decide(e)
        self.assertEqual(r["code"], "external-https-ready")
        self.assertTrue(r["external_https_ready"])
        self.assertFalse(r["host_deploy_handoff_ready"])
        self.assert_fail_closed(r)

    def test_external_verification_out_of_order_is_rejected(self):
        e = evidence()
        e["external"]["status"] = "verified"
        with self.assertRaisesRegex(StateError, "external verification is out of order"):
            validate_evidence(e)

    def test_headless_cli_reports_only_contract_status(self):
        e = evidence()
        e["policy"] = {
            "status": "missing",
            "hostname_approved": False,
            "challenge_approved": False,
            "challenge": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "certificate-evidence.json")
            path.write_text(json.dumps(e))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["certificate-status", str(path)]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(
            payload["result"]["code"],
            "awaiting-operator-approved-hostname-challenge",
        )
        self.assertNotIn("hostnames", payload["result"])
        self.assertNotIn("credentials", payload["result"])
        self.assert_fail_closed(payload["result"])


if __name__ == "__main__":
    unittest.main()
