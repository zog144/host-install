"""Source-only broker install/revocation contract; does not touch protected paths."""
import hashlib
import json
import uuid

import pytest

from zog.host_install import certificate_selected_broker_install as broker
from zog.host_install.state_contract import StateError, canonical


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def uid(n):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"selected-broker-{n}"))


def fixture():
    binding = {
        "schema": broker.PRIVATE_BINDING_SCHEMA,
        "host_id": uid(1),
        "installation_id": uid(2),
        "state_volume_id": uid(3),
        "registry_id": "primary",
        "authority_key_id": "1" * 64,
        "consumer": "host-nginx-https",
        "service_id": "nginx",
        "certificate_id": "station-web",
        "hostnames": ["example.org"],
        "policy_sha256": "2" * 64,
        "challenge": "dns-01",
        "dns_mode": "local-cloudflare",
        "dns_zone": "example.org",
        "credential_id": "zone1",
        "credential_revision": 4,
        "contact_email": "ops@example.org",
        "acme_directory": "https://acme.example.org/directory",
    }
    owner = {
        "schema": broker.OWNER_SCHEMA, "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": uid(1), "installation_id": uid(2),
        "certificate_id": "station-web", "service_id": "nginx",
        "hostnames": ["example.org"], "policy_sha256": "2" * 64,
        "challenge": "dns-01", "dns_mode": "local-cloudflare",
        "dns_zone": "example.org", "credential_id": "zone1",
        "credential_revision": 4,
        "operation_id": uid(4), "revision": 6,
        "approved_at": 50, "expires_at": 10000,
        "revoked_at": None, "status": "approved",
    }
    raw = canonical(binding)
    issuer = {"storage_id": "a" * 32, "grant_id": "b" * 32,
              "uid": 24001, "gid": 24002, "software_view": "sha256:" + "c" * 64,
              "certificate_data_path": "/var/lib/zog-certify-manage",
              "controller_record_sha256": "d" * 64}
    ledger = {
        "schema": broker.OWNER_LEDGER_SCHEMA,
        "installation_id": uid(2), "state_volume_id": uid(3),
        "registry_id": "primary", "authority_key_id": "1" * 64,
        "service_id": "nginx", "certificate_id": "station-web",
        "binding_sha256": hashlib.sha256(raw).hexdigest(),
        "delivery_policy_sha256": "2" * 64, "issuer": issuer,
        "local_intent_sha256": "3" * 64,
        "revision": 6, "operation_id": uid(4),
        "assignment_sha256": "4" * 64,
        "owner_authority_sha256": digest(owner),
        "status": "approved", "operations": [{
            "revision": 6, "operation_id": uid(4),
            "assignment_sha256": "4" * 64,
            "owner_authority_sha256": digest(owner), "status": "approved",
        }],
    }
    candidate = {
        "schema": broker.PROJECTION_SCHEMA,
        "host_id": uid(1), "installation_id": uid(2),
        "state_volume_id": uid(3), "certificate_id": "station-web",
        "hostnames": ["example.org"], "policy_sha256": "2" * 64,
        "host_policy_digest": "sha256:" + "5" * 64,
        "issuer_lifecycle_socket": "/run/zog/certify-lifecycle.sock",
        "controller_uid": 23001, "caller_uid": 23002,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "storage_id": "a" * 32, "grant_id": "b" * 32,
        "box_control_revision": broker.BOX_CONTROL_REVIEWED_COMMIT,
        "consumer_binding_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    approval = {
        **candidate, "schema": broker.APPROVAL_SCHEMA,
        "owner_revision": 6, "owner_operation_id": uid(4),
        "owner_authority_sha256": digest(owner),
        "root_owner_ledger_sha256": digest(ledger),
        "host_deploy_source_commit": broker.HOST_DEPLOY_REVIEWED_COMMIT,
    }
    args = {
        "approval_bytes": canonical(approval),
        "expected_approval_sha256": digest(approval),
        "private_binding_bytes": raw,
        "owner": owner, "root_owner_ledger": ledger,
        "host_policy_digest": candidate["host_policy_digest"], "now": 100,
    }
    return args


def test_current_root_approved_exact_projection_and_no_replace():
    args = fixture()
    plan = broker.projection_plan(**args)
    assert plan["path"] == broker.PROJECTION_PATH
    assert (plan["uid"], plan["gid"], plan["mode"]) == (0, 0, 0o444)
    assert plan["projection"]["controller_uid"] == 23001
    assert set(plan["projection"]) == broker.PROJECTION_FIELDS
    assert plan["projection_bytes"] == canonical(plan["projection"])
    assert plan["native_installation_authorized"] is False
    assert broker.no_replacement_check(None, plan["projection_bytes"]) == "new-only"
    assert broker.no_replacement_check(plan["projection_bytes"],
                                       plan["projection_bytes"]) == "same-byte-idempotent"
    with pytest.raises(StateError, match="installed-projection-conflict"):
        broker.no_replacement_check(b"forged", plan["projection_bytes"])
    with pytest.raises(StateError, match="revocation-tombstone-present"):
        broker.no_replacement_check(None, plan["projection_bytes"],
                                    revocation_present=True)


@pytest.mark.parametrize("field,foreign", [
    ("host_id", uid(90)), ("installation_id", uid(91)),
    ("state_volume_id", uid(92)), ("certificate_id", "other-cert"),
    ("hostnames", ["other.example.org"]), ("policy_sha256", "9"*64),
    ("controller_uid", 24001), ("caller_uid", 23001),
    ("issuer_uid", 23001), ("issuer_gid", 3),
    ("grant_id", "e"*32), ("storage_id", "f"*32),
    ("consumer_binding_sha256", "sha256:"+"f"*64),
    ("box_control_revision", "f"*40),
    ("host_deploy_source_commit", "f"*40),
    ("root_owner_ledger_sha256", "f"*64),
])
def test_independently_approved_invalid_identity_is_rejected(field, foreign):
    args = fixture()
    row = json.loads(args["approval_bytes"])
    row[field] = foreign
    args["approval_bytes"] = canonical(row)
    args["expected_approval_sha256"] = digest(row)
    with pytest.raises(StateError):
        broker.projection_plan(**args)


def test_self_asserted_root_approval_digest_and_root_ledger_drift_fail():
    args = fixture()
    args["expected_approval_sha256"] = "0"*64
    with pytest.raises(StateError, match="independent-approval-mismatch"):
        broker.projection_plan(**args)

    args = fixture()
    args["root_owner_ledger"]["revision"] += 1
    with pytest.raises(StateError):
        broker.projection_plan(**args)

    args = fixture()
    args["private_binding_bytes"] += b" "
    with pytest.raises(StateError):
        broker.projection_plan(**args)

    args = fixture()
    args["owner"]["expires_at"] = 100
    with pytest.raises(StateError):
        broker.projection_plan(**args)


def installed_and_revoked():
    args = fixture()
    install = broker.projection_plan(**args)
    installed = {
        **install["receipt"], "status": "installed",
        "native_installation_verified": True,
    }
    revoked_owner = {
        **args["owner"], "revision": 7,
        "operation_id": uid(7), "status": "revoked",
        "revoked_at": 110, "expires_at": 110,
    }
    revoked_ledger = {
        **args["root_owner_ledger"], "revision": 7,
        "operation_id": uid(7), "status": "revoked",
        "owner_authority_sha256": digest(revoked_owner),
    }
    approval = {
        "schema": broker.REVOCATION_APPROVAL_SCHEMA,
        "projection_sha256": hashlib.sha256(install["projection_bytes"]).hexdigest(),
        "install_receipt_sha256": digest(installed),
        "root_owner_ledger_sha256": digest(revoked_ledger),
        "revoked_revision": 7, "revoked_operation_id": uid(7),
        "host_id": install["projection"]["host_id"],
        "installation_id": install["projection"]["installation_id"],
        "state_volume_id": install["projection"]["state_volume_id"],
        "certificate_id": install["projection"]["certificate_id"],
    }
    return {
        "projection_bytes": install["projection_bytes"],
        "install_receipt": installed,
        "revoked_owner": revoked_owner,
        "revoked_ledger": revoked_ledger,
        "approval_bytes": canonical(approval),
        "expected_approval_sha256": digest(approval),
    }


def test_signed_owner_revocation_yields_irreversible_no_replace_tombstone():
    args = installed_and_revoked()
    result = broker.revocation_plan(**args)
    assert result["path"] == broker.REVOCATION_PATH
    assert result["irreversible"] is True
    assert (result["uid"], result["gid"], result["mode"]) == (0, 0, 0o444)
    assert json.loads(result["tombstone_bytes"])["revoked_revision"] == 7
    assert broker.no_replacement_check(result["tombstone_bytes"],
                                       result["tombstone_bytes"]) == "same-byte-idempotent"


@pytest.mark.parametrize("attack", [
    "no-native-proof", "rollback", "wrong-signed-owner", "foreign-installation",
    "wrong-revocation-approval", "wrong-projection", "same-revision",
])
def test_revocation_fails_closed_on_stale_or_forged_evidence(attack):
    args = installed_and_revoked()
    if attack == "no-native-proof":
        args["install_receipt"]["native_installation_verified"] = False
    if attack == "rollback":
        args["revoked_ledger"]["revision"] = 5
    if attack == "same-revision":
        args["revoked_ledger"]["revision"] = 6
        args["revoked_owner"]["revision"] = 6
    if attack == "wrong-signed-owner":
        args["revoked_owner"]["host_id"] = uid(99)
    if attack == "foreign-installation":
        args["revoked_ledger"]["installation_id"] = uid(99)
    if attack == "wrong-revocation-approval":
        args["expected_approval_sha256"] = "f"*64
    if attack == "wrong-projection":
        args["projection_bytes"] += b" "
    with pytest.raises(StateError):
        broker.revocation_plan(**args)


def test_no_proposal_only_revocation():
    args = installed_and_revoked()
    args["install_receipt"]["status"] = "source-plan-only"
    with pytest.raises(StateError, match="original-install-receipt-mismatch"):
        broker.revocation_plan(**args)



# Privileged synthetic filesystem tests: only a temporary directory descriptor,
# never the real /etc or STATE. The real native owner still must attest sources.
@pytest.mark.skipif(__import__("os").geteuid() != 0,
                    reason="root-owned descriptor publication requires root")
def test_protected_root_publication_and_irreversible_revoke(tmp_path, monkeypatch):
    from contextlib import contextmanager
    import os

    @contextmanager
    def simulated_root_parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(broker, "_fixed_root_parent", simulated_root_parent)
    source = fixture()
    kwargs = {
        "trusted_original_root_reader": lambda: {k: v for k, v in source.items() if k != "expected_approval_sha256"},
        "trusted_source_attestor": lambda plan: True,
        "expected_approval_sha256": source["expected_approval_sha256"],
    }
    installed = broker.publish_verified_projection(**kwargs)
    assert installed["status"] == "installed"
    assert installed["native_installation_verified"] is True
    projected_path = tmp_path / broker.PROJECTION_NAME
    receipt_path = tmp_path / broker.INSTALL_RECEIPT_NAME
    assert projected_path.is_file() and receipt_path.is_file()
    original_inodes = (projected_path.stat().st_ino, receipt_path.stat().st_ino)
    assert broker.publish_verified_projection(**kwargs) == installed
    assert (projected_path.stat().st_ino, receipt_path.stat().st_ino) == original_inodes

    # The protected source verifier cannot be bypassed just by having a
    # syntactically valid operator digest and a root-owned directory.
    with pytest.raises(StateError, match="installed-source-attestation-missing"):
        broker.publish_verified_projection(**{
            **kwargs, "trusted_source_attestor": lambda _: False,
        })

    revoked = installed_and_revoked()
    result = broker.publish_verified_revocation(
        trusted_original_revocation_reader=lambda: {
            k: revoked[k] for k in ("revoked_owner", "revoked_ledger", "approval_bytes")
        },
        trusted_source_attestor=lambda _: True,
        expected_approval_sha256=revoked["expected_approval_sha256"],
    )
    marker = tmp_path / broker.REVOCATION_NAME
    assert marker.stat().st_ino > 0
    assert result["status"] == "root-owned-revocation-tombstone-retained"
    assert result["production_activation_authorized"] is False
    assert broker.publish_verified_revocation(
        trusted_original_revocation_reader=lambda: {
            k: revoked[k] for k in ("revoked_owner", "revoked_ledger", "approval_bytes")
        },
        trusted_source_attestor=lambda _: True,
        expected_approval_sha256=revoked["expected_approval_sha256"],
    ) == result
    with pytest.raises(StateError, match="revocation-tombstone-present"):
        broker.publish_verified_projection(**kwargs)
    assert (projected_path.stat().st_ino, receipt_path.stat().st_ino) == original_inodes


@pytest.mark.skipif(__import__("os").geteuid() != 0,
                    reason="root-owned descriptor publication requires root")
@pytest.mark.parametrize("name,point", [
    ("certificate-issuer-broker-authority.json", "staged"),
    ("certificate-issuer-broker-authority.json", "linked"),
    ("certificate-issuer-broker-authority.json", "published"),
    ("certificate-issuer-broker-install-receipt.json", "staged"),
    ("certificate-issuer-broker-install-receipt.json", "linked"),
    ("certificate-issuer-broker-install-receipt.json", "published"),
])
def test_interrupted_root_publication_is_same_byte_recoverable(
        tmp_path, monkeypatch, name, point):
    import os
    from contextlib import contextmanager

    @contextmanager
    def simulated_root_parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(broker, "_fixed_root_parent", simulated_root_parent)
    original_publish = broker.publish
    def fault(fd, filename, data, *, mode, uid, gid):
        def at(checkpoint):
            if checkpoint == f"{point}:{name}":
                raise RuntimeError("interrupted-protected-writer")
        return original_publish(fd, filename, data, mode=mode, uid=uid,
                                gid=gid, checkpoint=at)
    root = fixture()
    kwargs = {
        "trusted_original_root_reader": lambda: {k: v for k, v in root.items() if k != "expected_approval_sha256"},
        "trusted_source_attestor": lambda _: True,
        "expected_approval_sha256": root["expected_approval_sha256"],
    }
    with monkeypatch.context() as patcher:
        patcher.setattr(broker, "publish", fault)
        with pytest.raises(RuntimeError, match="interrupted-protected-writer"):
            broker.publish_verified_projection(**kwargs)
    original = {name: (tmp_path / name).stat().st_ino
                for name in (broker.PROJECTION_NAME, broker.INSTALL_RECEIPT_NAME)
                if (tmp_path / name).exists()}
    broker.publish_verified_projection(**kwargs)
    assert all((tmp_path / name).stat().st_ino == inode
               for name, inode in original.items())
    assert set(os.listdir(tmp_path)) == {
        broker.PROJECTION_NAME, broker.INSTALL_RECEIPT_NAME, broker.LOCK_NAME,
    }



@pytest.mark.skipif(__import__("os").geteuid() != 0,
                    reason="root-owned descriptor publication requires root")
@pytest.mark.parametrize("moment", ("staged", "linked", "published"))
def test_interrupted_root_revocation_never_reenables_projection(
        tmp_path, monkeypatch, moment):
    import os
    from contextlib import contextmanager

    @contextmanager
    def root_parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(broker, "_fixed_root_parent", root_parent)
    source = fixture()
    broker.publish_verified_projection(
        trusted_original_root_reader=lambda: {k: v for k, v in source.items() if k != "expected_approval_sha256"},
        trusted_source_attestor=lambda _: True,
        expected_approval_sha256=source["expected_approval_sha256"],
    )
    evidence = installed_and_revoked()
    kwargs = {
        "trusted_original_revocation_reader": lambda: {
            k: evidence[k] for k in ("revoked_owner", "revoked_ledger", "approval_bytes")
        },
        "trusted_source_attestor": lambda _: True,
        "expected_approval_sha256": evidence["expected_approval_sha256"],
    }
    original = broker.publish
    def fault(fd, filename, data, *, mode, uid, gid):
        def checkpoint(step):
            if step == f"{moment}:{broker.REVOCATION_NAME}":
                raise RuntimeError("revocation-publish-interrupted")
        return original(fd, filename, data, mode=mode, uid=uid, gid=gid,
                        checkpoint=checkpoint)

    with monkeypatch.context() as patcher:
        patcher.setattr(broker, "publish", fault)
        with pytest.raises(RuntimeError, match="revocation-publish-interrupted"):
            broker.publish_verified_revocation(**kwargs)
    assert any((tmp_path / name).exists() for name in (
        broker.REVOCATION_NAME, ".pending." + broker.REVOCATION_NAME
    ))
    # Even an interrupted revocation is a permanent deny for the old
    # projection; source reattempt must preserve the original file inode.
    projection_inode = (tmp_path / broker.PROJECTION_NAME).stat().st_ino
    with pytest.raises(StateError, match="revocation-tombstone-present"):
        broker.publish_verified_projection(
            trusted_original_root_reader=lambda: {k: v for k, v in source.items() if k != "expected_approval_sha256"},
            trusted_source_attestor=lambda _: True,
            expected_approval_sha256=source["expected_approval_sha256"],
        )
    receipt = broker.publish_verified_revocation(**kwargs)
    assert receipt["status"] == "root-owned-revocation-tombstone-retained"
    assert (tmp_path / broker.PROJECTION_NAME).stat().st_ino == projection_inode
    assert not (tmp_path / (".pending." + broker.REVOCATION_NAME)).exists()


@pytest.mark.skipif(__import__("os").geteuid() != 0,
                    reason="root-owned descriptor publication requires root")
def test_root_owner_changes_between_preflight_and_publication_fail_closed(
        tmp_path, monkeypatch):
    import os
    from contextlib import contextmanager
    @contextmanager
    def root_parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)
    monkeypatch.setattr(broker, "_fixed_root_parent", root_parent)
    source = fixture()
    calls = [0]
    def changed_reader():
        calls[0] += 1
        if calls[0] == 1:
            return {k: v for k, v in source.items() if k != "expected_approval_sha256"}
        return {**{k: v for k, v in source.items() if k != "expected_approval_sha256"}, "host_policy_digest": "sha256:"+"0"*64}
    with pytest.raises(StateError, match="root-authority-changed-before-publication"):
        broker.publish_verified_projection(
            trusted_original_root_reader=changed_reader,
            trusted_source_attestor=lambda _: True,
            expected_approval_sha256=source["expected_approval_sha256"],
        )
    assert not (tmp_path / broker.PROJECTION_NAME).exists()
