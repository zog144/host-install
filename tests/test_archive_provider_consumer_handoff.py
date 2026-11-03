"""Actual archive-mirror consumer integration using *synthetic* signed deliveries.

No network, provider credentials, Host STATE, real issuer keys, or services.
"""
from __future__ import annotations
import json
from pathlib import Path
import uuid

import pytest
from django.conf import settings
if not settings.configured:
    # The actual pinned archive model imports require an initialized Django
    # app registry, but this test never opens a database or production config.
    settings.configure(
        INSTALLED_APPS=["zog.archive_mirror"],
        DATABASES={"default":{"ENGINE":"django.db.backends.sqlite3",
                              "NAME":":memory:"}},
        SECRET_KEY="synthetic-offline-review-only",
        USE_TZ=True,
    )
import django
django.setup()
from zog.host_identify import archive_credentials as ac
from zog.host_identify import credential_delivery as cd
from zog.host_install.archive_provider_handoff import ArchiveProviderHandoff
from zog.host_install.archive_provider_receiver import ReceiverHold, OfflineArchiveReceiver
from zog.archive_mirror import provider_credentials as provider
from zog.archive_mirror import store

from test_archive_provider_receiver_owner import fixtures, ISSUER


def scene(tmp_path,monkeypatch):
    path,receiver,args,auth,signer,request=fixtures(tmp_path)
    root=tmp_path/"archive-store"
    root.mkdir(mode=0o700)
    scope=args["scope"];selected=ac.provider_scope(scope)
    config={"root":str(root),"collections":["sources"]}
    monkeypatch.setattr(provider,"configuration",lambda:config)
    monkeypatch.setattr(store,"configuration",lambda:config)
    monkeypatch.setattr(provider,"lease",lambda:{
        "host_id":selected["host_id"],
        "desired":{"revision":selected["role_revision"],"selected":True}
    })
    # Synthetic native witness checks the actual archived private bytes
    # and exact identity, rather than accepting a caller-supplied boolean.
    def independent_witness(scope, req, delivery, receipt, app):
        with provider.open_for(scope,operation="fetch",collection="sources") as stream:
            stored=stream.read()
        return (stored==b"test-secret" and
                app["delivery_id"]==delivery["delivery_id"] and
                receipt["delivery_id"]==delivery["delivery_id"] and
                req["request_id"]==receipt["request_id"])
    bridge=ArchiveProviderHandoff(
        receiver=receiver,expected_scope=scope,
        authority_public_key=signer.public_key(),
        expected_issuer=ISSUER,native_witness=independent_witness,enabled=True)
    delivery={
        "schema":cd.DELIVERY_SCHEMA,"request_id":request["request_id"],
        "delivery_id":str(uuid.uuid4()),
        "authorization_id":auth["authorization_id"],
        "authorization_revision":auth["revision"],
        "credential_id":auth["credential_id"],
        "credential_revision":auth["credential_revision"],
        "consumer":"archive-mirror",
        "purpose":"archive-mirror-upstream-fetch",
        "issued_at":args["now"]-1,"expires_at":args["now"]+60,
        "secret_format":"base64","secret":"dGVzdC1zZWNyZXQ=",
    }
    signed_delivery=cd.sign_delivery(delivery,signer)
    receipt={
        "schema":cd.RECEIPT_SCHEMA,**ac.provider_binding(scope),
        "credential_revision":request["credential_revision"],
        "authorization_id":request["authorization_id"],
        "authorization_revision":request["authorization_revision"],
        "request_id":request["request_id"],"delivery_id":delivery["delivery_id"],
        "receipt_id":str(uuid.uuid4()),"outcome":"installed",
        "installed_at":args["now"],
    }
    return bridge,args,signer,auth,request,delivery,signed_delivery,receipt,root


def deliver(bridge,args,request,signed_delivery):
    assert bridge.claim(signed_authorization=args["signed_authorization"],
                        url=args["url"],method=args["method"],
                        headers=args["headers"],body=args["body"],
                        host_public_key=args["host_public_key"],now=args["now"])["status"]=="claimed"
    return bridge.deliver_once(
        signed_authorization=args["signed_authorization"],
        request=request,signed_delivery=signed_delivery,now=args["now"])


def test_real_archive_consumer_install_and_receipt_once(tmp_path,monkeypatch):
    bridge,args,_,_,req,delivery,signed,receipt,root=scene(tmp_path,monkeypatch)
    assert deliver(bridge,args,req,signed)=={
        "status":"consumer-installed-receipt-pending",
        "delivery_id":delivery["delivery_id"]}
    assert bridge.receiver.inspect_handoff()["status"]=="installing"
    app=provider.inspect(args["scope"])
    assert app["status"]=="installed" and app["delivery_id"]==delivery["delivery_id"]
    assert bridge.reconcile_receipt(receipt=receipt,request=req,delivery=delivery,
                                    now=args["now"])["status"]=="receipt-durable"
    assert bridge.receiver.inspect_handoff()["status"]=="installed"
    with pytest.raises((ReceiverHold,ValueError)):
        bridge.deliver_once(signed_authorization=args["signed_authorization"],
                            request=req,signed_delivery=signed,now=args["now"])
    ledger=(bridge.receiver.directory/"archive-provider-ledger.json").read_text()
    assert "test-secret" not in ledger and "dGVzdC1zZWNyZXQ=" not in ledger
    assert not any("dGVzdC1zZWNyZXQ" in p.read_text(errors="ignore")
                   for p in bridge.receiver.directory.glob("*.json"))


def test_crash_after_archive_commit_cannot_redeliver_and_can_reconcile(tmp_path,monkeypatch):
    bridge,args,_,_,req,delivery,signed,receipt,root=scene(tmp_path,monkeypatch)
    original=provider.install_verified
    called=[]
    def crash_after_durable_archive_install(*a,**k):
        called.append(1)
        original(*a,**k) # genuine protected archive consumer source
        raise RuntimeError("lost archive install acknowledgement")
    monkeypatch.setattr(provider,"install_verified",crash_after_durable_archive_install)
    assert bridge.claim(signed_authorization=args["signed_authorization"],
                        url=args["url"],method=args["method"],
                        headers=args["headers"],body=args["body"],
                        host_public_key=args["host_public_key"],now=args["now"])["status"]=="claimed"
    with pytest.raises(RuntimeError,match="lost archive"):
        bridge.deliver_once(signed_authorization=args["signed_authorization"],
                            request=req,signed_delivery=signed,now=args["now"])
    assert len(called)==1
    assert bridge.receiver.inspect_handoff()["status"]=="installing"
    # Recreate the receiver from durable ledger and do NOT invoke consumer.
    bridge.receiver=OfflineArchiveReceiver(bridge.receiver.directory,enabled=True)
    with pytest.raises(ReceiverHold):
        bridge.deliver_once(signed_authorization=args["signed_authorization"],
                            request=req,signed_delivery=signed,now=args["now"])
    assert called==[1]
    assert provider.inspect(args["scope"])["delivery_id"]==delivery["delivery_id"]
    assert bridge.reconcile_receipt(receipt=receipt,request=req,delivery=delivery,
                                    now=args["now"])["status"]=="receipt-durable"
    assert called==[1]


def test_missing_independent_archive_receipt_witness_remains_held(tmp_path,monkeypatch):
    bridge,args,_,_,req,delivery,signed,receipt,root=scene(tmp_path,monkeypatch)
    deliver(bridge,args,req,signed)
    bridge.native_witness=lambda *a:False
    with pytest.raises(ReceiverHold,match="witness denied"):
        bridge.reconcile_receipt(receipt=receipt,request=req,delivery=delivery,
                                 now=args["now"])
    assert bridge.receiver.inspect_handoff()["status"]=="installing"
    with pytest.raises(ReceiverHold):
        bridge.deliver_once(signed_authorization=args["signed_authorization"],
                            request=req,signed_delivery=signed,now=args["now"])


def test_real_signed_revocation_blocks_archive_secret_without_removing_objects(tmp_path,monkeypatch):
    bridge,args,authority,auth,req,delivery,signed,receipt,root=scene(tmp_path,monkeypatch)
    deliver(bridge,args,req,signed)
    bridge.reconcile_receipt(receipt=receipt,request=req,delivery=delivery,now=args["now"])
    # Retained objects are independent of provider credential tombstone.
    retained=root/"objects";retained.mkdir()
    object_path=retained/("a"*64)
    object_path.write_bytes(b"retained-object")
    revoked={**auth,"status":"revoked","revision":auth["revision"]+1,
             "revoked_at":args["now"]}
    envelope=cd.sign_authorization(revoked,authority)
    assert bridge.apply_revocation(signed_revocation=envelope,now=args["now"])["status"]=="receiver-and-archive-revoked"
    assert bridge.receiver.inspect_handoff()["revoked"] is True
    assert provider.inspect(args["scope"])["reason"]=="authorization-revoked"
    with pytest.raises(provider.ProviderCredentialError):
        provider.open_for(args["scope"],operation="fetch",collection="sources")
    assert object_path.read_bytes()==b"retained-object"
    with pytest.raises((ReceiverHold,ValueError)):
        bridge.claim(signed_authorization=args["signed_authorization"],
                     url=args["url"],method=args["method"],
                     headers=args["headers"],body=args["body"],
                     host_public_key=args["host_public_key"],now=args["now"])


def test_rejected_cross_consumer_authority_scope_and_disabled(tmp_path,monkeypatch):
    bridge,args,_,_,req,delivery,signed,receipt,root=scene(tmp_path,monkeypatch)
    with pytest.raises(ReceiverHold,match="disabled"):
        ArchiveProviderHandoff(
            receiver=bridge.receiver,expected_scope=args["scope"],
            authority_public_key=bridge.authority_public_key,
            expected_issuer=ISSUER,native_witness=bridge.native_witness)
    forged=dict(args["scope"]);forged["provider_role"]="cloudflare"
    with pytest.raises((ValueError,ReceiverHold)):
        ArchiveProviderHandoff(
            receiver=bridge.receiver,expected_scope=forged,
            authority_public_key=bridge.authority_public_key,
            expected_issuer=ISSUER,native_witness=bridge.native_witness,
            enabled=True)
    altered=dict(req);altered["request_id"]=str(uuid.uuid4())
    bridge.claim(signed_authorization=args["signed_authorization"],
                 url=args["url"],method=args["method"],
                 headers=args["headers"],body=args["body"],
                 host_public_key=args["host_public_key"],now=args["now"])
    with pytest.raises((ValueError,ReceiverHold)):
        bridge.deliver_once(signed_authorization=args["signed_authorization"],
                            request=altered,signed_delivery=signed,now=args["now"])
    assert provider.inspect(args["scope"])["status"]=="unavailable"
