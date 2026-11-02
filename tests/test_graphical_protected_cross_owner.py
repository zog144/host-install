"""Three-owner synthetic graphical authority install/rollback acceptance.

root-control issuer + protected host-install installer + host-deploy gateway.
No native keys or external services.
"""
import base64
import hashlib
import json
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.root_control.graphical_monotonic_issuer import Issuer
from zog.host_deploy.gateway import graphics_external_checkpoint as gateway
from zog.host_install import graphical_protected_authority_install as protected
from zog.host_install import graphical_checkpoint_transport as transport
from zog.host_install import graphical_current_authority as g
from test_graphical_protected_authority_install import authority,put
from test_graphical_current_authority import pin,public

def test_issuer_installer_gateway_exact_current_signer(
        authority,tmp_path,monkeypatch):
    install,args,public_dir,private_dir,remote,operator,keys,fds=authority
    external_dir=tmp_path/"external-nonhost-test-storage"
    external_dir.mkdir(mode=0o700)
    external_fd=os.open(external_dir,os.O_RDONLY|os.O_DIRECTORY)
    try:
        issuer=Issuer(external_fd,signer=Ed25519PrivateKey.generate(),
                      owner_uid=os.geteuid())
        external_key=issuer.public_key
        anchor={
            "schema":transport.PIN_SCHEMA,
            "host_id":"host-approved",
            "installation_id":"installation-approved",
            "external_public_key":base64.b64encode(external_key).decode(),
            "external_key_sha256":hashlib.sha256(external_key).hexdigest(),
            "relay_uid":23009,
        }
        # Regenerate only the synthetic independently signed original grant:
        # source/native test has not yet installed any Host authority.
        original_path=private_dir/protected.ORIGINAL_GRANT
        grant=json.loads(original_path.read_bytes())
        unsigned={k:v for k,v in grant.items() if k!="signature_ed25519"}
        unsigned["external_key_sha256"]=anchor["external_key_sha256"]
        sig=install.original_identity_signer.sign(
            protected.GRANT_DOMAIN+g.canonical(unsigned))
        raw=g.canonical({**unsigned,"signature_ed25519":
            base64.b64encode(sig).decode()})
        put(original_path,raw)
        source_path=private_dir/protected.SOURCE_ATTESTATION
        source=json.loads(source_path.read_bytes())
        source["original_grant_sha256"]=g._sha(raw)
        put(source_path,g.canonical(source))
        monkeypatch.setattr(transport,"installed",lambda:(anchor,external_key))
        monkeypatch.setattr(transport,"read",lambda nonce:issuer.read_signed(
            host_id="host-approved",installation_id="installation-approved",
            nonce=nonce))
        def cas(**kwargs):
            issuer.compare_and_advance(
                **kwargs,operation_id="rotation-"+kwargs["next_approval_sha256"])
        monkeypatch.setattr(transport,"advance",cas)
        gateway_anchor={
            "schema":gateway.PIN_SCHEMA,
            "host_id":"host-approved","installation_id":"installation-approved",
            "external_public_key":anchor["external_public_key"],
            "external_key_sha256":anchor["external_key_sha256"],
            "relay_uid":23009,
        }
        monkeypatch.setattr(gateway,"_installed_pin",
                            lambda:(gateway_anchor,external_key))
        monkeypatch.setattr(gateway,"_exchange",lambda nonce,pin:issuer.read_signed(
            host_id=pin["host_id"],installation_id=pin["installation_id"],
            nonce=nonce))
        assert install(1)["epoch"]==1
        assert gateway.require_current(pin(keys[0],1))["epoch"]==1
        assert install(2)["epoch"]==2
        assert gateway.require_current(pin(keys[1],2))["epoch"]==2
        # Current remote highwater refuses still-valid old signed Host key.
        with pytest.raises(gateway.CheckpointBlocked):
            gateway.require_current(pin(keys[0],1))
        # Roll back BOTH public and private local authority files. Independent
        # root-control issuer retains epoch 2 and gateway cannot read epoch 1.
        old=current1=pin(keys[0],1)
        (public_dir/g.PUBLIC_NAME).unlink()
        (public_dir/g.PUBLIC_NAME).write_bytes(g.canonical(old))
        (public_dir/g.PUBLIC_NAME).chmod(0o444)
        journal=private_dir/g.PRIVATE_JOURNAL
        current_journal=json.loads(journal.read_bytes())
        current_journal.update(epoch=1,current_sha256=g._sha(g.canonical(old)),
                               approval_sha256=g._sha(args(1)["approval_bytes"]))
        journal.unlink()
        journal.write_bytes(g.canonical(current_journal))
        journal.chmod(0o600)
        with pytest.raises(gateway.CheckpointBlocked):
            gateway.require_current(old)
        with pytest.raises(g.RotationDenied):
            install(1)
        assert issuer.read_signed(host_id="host-approved",
                installation_id="installation-approved",nonce="a"*48)
    finally:
        os.close(external_fd)


def test_root_imported_source_identity_is_not_native_approval():
    # Exact production entrypoint cannot accept a synthetic issuer callback.
    with pytest.raises(TypeError):
        protected.install_current_authority(
            approved_pin_bytes=b"{}",approval_bytes=b"{}",
            independently_trusted_source_reader=lambda:True)
