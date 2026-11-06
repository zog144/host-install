"""One trusted administrative Host: source-only admission is not admin-isolation proof."""
import json
import inspect
from pathlib import Path

from zog.host_install import graphical_native_owner_install as owner
from zog.host_install import graphical_readonly_trust_broker_install as broker
from test_graphical_native_owner_install import row


ROOT = Path(__file__).resolve().parents[1]


def test_selected_same_host_contract_and_original_owner_holds():
    model = json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())
    assert model["schema"] == "zog-graphical-shared-host-trust-model-v1"
    assert model["administrator_can_access_local_ssm_authority"] is True
    assert model["root_admin_inaccessibility_proof_required"] is False
    assert model["normal_owner_path_bypass_permitted"] is False
    assert model["actions_oidc_permissions"] == "sqs_dispatch_only"
    assert model["read_only_broker_getobject_only_required"] is True
    assert model["original_s3_history_and_genesis_required"] is True
    assert owner.validate_install_contract(row())["status"] == "NOT_ACTIVATED"


def test_gateway_service_policy_is_not_accepted_iam_or_root_denial():
    # This is an *optional* service-level policy template, not proof of
    # effective IAM and definitely not a capability boundary against root.
    template = owner.required_gateway_denial()
    assert template["Statement"][0]["Effect"] == "Deny"
    result = owner.verify_gateway_denial_policy(template)
    assert result["aws_iam_verified"] is False
    assert result["native_service_enabled"] is False
    assert "gateway_send_denied" not in owner.validate_install_contract(row())
    # The source contract records only unaccepted evidence booleans.
    assert owner.validate_install_contract(row())["gateway_iam_explicit_deny_verified"] is False
    assert owner.validate_install_contract(row())["gateway_imds_and_sts_denial_verified"] is False


def test_separate_selected_logical_roles_and_disabled_broker_preserved():
    model = json.loads((ROOT/"docs/graphical-task-c-shared-host-trust-v1.json").read_text())
    assert model["separate_cryptographic_role_identities_required"] is True
    assert model["separate_physical_signing_hosts_required"] is False
    assert owner.OWNER_PYTHON != broker.BROKER_PYTHON
    assert owner.CREDS != broker.READ_SOURCE
    assert owner.LEDGER == broker.ORIGINAL_LEDGER
