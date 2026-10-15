"""Pure fail-closed certificate application enablement/status policy.

The caller supplies already-authenticated owner evidence. This module does not
authenticate grants, policy files, certificates, controller sessions, or service
state and MUST NOT be exposed as an authorization service. It never invokes
certify-manage, Certbot, host-deploy, nginx, or archive controls.
"""
import re

from .state_contract import fields, require

SCHEMA = 1
KIND = "zog-certificate-enablement-evidence"
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def _token(value, name, *, optional=False):
    if optional and value is None:
        return
    require(type(value) is str and _TOKEN.fullmatch(value) is not None,
            "certificate-evidence", name)


def validate_evidence(evidence):
    fields(evidence, "schema kind state grant software policy persistent preparation issuance publication external")
    require(evidence["schema"] == SCHEMA and evidence["kind"] == KIND,
            "certificate-evidence", "unsupported certificate enablement schema")

    state = evidence["state"]
    fields(state, "verified recovery_hold")
    require(type(state["verified"]) is bool and type(state["recovery_hold"]) is bool,
            "certificate-evidence", "state")

    grant = evidence["grant"]
    fields(grant, "status grant_id")
    require(grant["status"] in ("verified", "missing", "revoked", "invalid"),
            "certificate-evidence", "grant status")
    _token(grant["grant_id"], "grant id", optional=grant["status"] != "verified")
    if grant["status"] == "verified":
        require(grant["grant_id"] is not None, "certificate-evidence", "verified grant id required")

    software = evidence["software"]
    fields(software, "status generation")
    require(software["status"] in ("verified", "missing", "invalid"),
            "certificate-evidence", "software status")
    _token(software["generation"], "software generation", optional=software["status"] != "verified")
    if software["status"] == "verified":
        require(software["generation"] is not None,
                "certificate-evidence", "verified software generation required")

    policy = evidence["policy"]
    fields(policy, "status hostname_approved challenge_approved challenge")
    require(policy["status"] in ("approved", "missing", "invalid", "revoked", "conflict", "migration-required"),
            "certificate-evidence", "policy status")
    require(type(policy["hostname_approved"]) is bool and
            type(policy["challenge_approved"]) is bool,
            "certificate-evidence", "policy approvals")
    require(policy["challenge"] in (None, "http-01", "dns-01"),
            "certificate-evidence", "challenge")
    if policy["status"] == "approved":
        require(policy["hostname_approved"] and policy["challenge_approved"] and
                policy["challenge"] in ("http-01", "dns-01"),
                "certificate-evidence", "approved policy is incomplete")

    persistent = evidence["persistent"]
    fields(persistent, "status existing_acme_identity lineage_status replacement_attempted")
    require(persistent["status"] in ("available", "missing", "unavailable", "uncertain"),
            "certificate-evidence", "persistent state status")
    require(type(persistent["existing_acme_identity"]) is bool and
            type(persistent["replacement_attempted"]) is bool,
            "certificate-evidence", "persistent state flags")
    require(persistent["lineage_status"] in ("absent", "healthy", "uncertain", "conflict"),
            "certificate-evidence", "lineage status")
    preparation = evidence["preparation"]
    fields(preparation, "status")
    require(preparation["status"] in ("not-run", "complete", "failed"),
            "certificate-evidence", "preparation status")

    issuance = evidence["issuance"]
    fields(issuance, "status local_verified")
    require(issuance["status"] in ("not-started", "pending", "issued", "failed", "uncertain"),
            "certificate-evidence", "issuance status")
    require(type(issuance["local_verified"]) is bool,
            "certificate-evidence", "issuance verification")
    if issuance["local_verified"]:
        require(issuance["status"] == "issued",
                "certificate-evidence", "only issued certificates can be locally verified")

    publication = evidence["publication"]
    fields(publication, "status")
    require(publication["status"] in
            ("not-started", "issuer-staged", "delivered", "loaded", "failed", "rolled-back"),
            "certificate-evidence", "publication status")

    external = evidence["external"]
    fields(external, "status")
    require(external["status"] in ("not-verified", "verified", "failed"),
            "certificate-evidence", "external status")
    if external["status"] == "verified":
        require(publication["status"] == "loaded" and
                issuance["status"] == "issued" and issuance["local_verified"],
                "certificate-evidence", "external verification is out of order")
    return evidence


def decide(evidence):
    """Return secret-free status and the next host-owner lifecycle boundary."""
    validate_evidence(evidence)

    persistent = evidence["persistent"]
    identity_action = ("preserve-existing" if persistent["existing_acme_identity"]
                       else "create-only-on-authorized-issuance")

    def result(status, code, next_step, *, issue=False, deploy=False, ready=False):
        return {
            "status": status,
            "code": code,
            "next_step": next_step,
            "identity_action": identity_action,
            "issuance_allowed": issue,
            "host_deploy_handoff_ready": deploy,
            "external_https_ready": ready,
            # These are deliberately never granted by host-install.
            "self_signed_allowed": False,
            "public_auto_issuance_allowed": False,
            "proxy_exposure_allowed": False,
            "archive_role_change_allowed": False,
            "station_observer_mtls_separate": True,
        }

    state = evidence["state"]
    if not state["verified"]:
        return result("blocked", "state-unverified", "verify-state")
    if state["recovery_hold"]:
        return result("blocked", "recovery-required", "operator-reconciliation")

    grant = evidence["grant"]
    if grant["status"] != "verified":
        return result("blocked", "application-grant-" + grant["status"],
                      "obtain-controller-issued-application-grant")

    software = evidence["software"]
    if software["status"] != "verified":
        return result("blocked", "software-generation-" + software["status"],
                      "select-verified-immutable-software-generation")

    policy = evidence["policy"]
    if policy["status"] == "missing":
        return result("awaiting-operator",
                      "awaiting-operator-approved-hostname-challenge",
                      "approve-hostname-and-challenge")
    if policy["status"] != "approved":
        return result("blocked", "certificate-policy-" + policy["status"],
                      "operator-reconciliation")
    if (not policy["hostname_approved"] or not policy["challenge_approved"] or
            policy["challenge"] not in ("http-01", "dns-01")):
        return result("blocked", "certificate-policy-incomplete",
                      "operator-reconciliation")

    if persistent["status"] != "available":
        return result("blocked", "persistent-state-" + persistent["status"],
                      "restore-protected-certificate-state")
    if persistent["existing_acme_identity"] and persistent["replacement_attempted"]:
        return result("blocked", "acme-identity-regeneration-forbidden",
                      "preserve-existing-acme-identity")
    if persistent["lineage_status"] in ("uncertain", "conflict"):
        return result("blocked", "certificate-lineage-" + persistent["lineage_status"],
                      "operator-reconciliation")

    preparation = evidence["preparation"]["status"]
    if preparation == "failed":
        return result("blocked", "application-preparation-failed",
                      "operator-reconciliation")
    if preparation != "complete":
        return result("ready", "application-preparation-required",
                      "prepare-application-once")

    issuance = evidence["issuance"]
    if issuance["status"] == "failed":
        return result("blocked", "certificate-issuance-failed",
                      "operator-review")
    if issuance["status"] == "uncertain":
        return result("blocked", "certificate-issuance-uncertain",
                      "operator-reconciliation")
    if issuance["status"] == "pending":
        return result("pending", "certificate-issuance-pending",
                      "wait-for-authorized-issuance")
    if issuance["status"] == "not-started":
        return result("ready", "ready-for-authorized-issuance",
                      "request-authorized-issuance", issue=True)
    if not issuance["local_verified"]:
        return result("blocked", "local-certificate-unverified",
                      "inspect-and-verify-issued-certificate")

    publication = evidence["publication"]["status"]
    if publication in ("failed", "rolled-back"):
        return result("blocked", "certificate-publication-" + publication,
                      "host-deploy-reconciliation")
    if publication in ("not-started", "issuer-staged", "delivered"):
        return result("ready", "host-deploy-publication-required",
                      "request-authorized-host-deploy-publication", deploy=True)

    external = evidence["external"]["status"]
    if external == "failed":
        return result("blocked", "external-https-verification-failed",
                      "host-deploy-reconciliation")
    if external != "verified":
        return result("pending", "external-https-verification-required",
                      "verify-external-https")
    return result("ready", "external-https-ready", "none", ready=True)
