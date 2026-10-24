# Managed certificate owner authority and prepared issuer handoff

**Status:** host-install source contract. Native authority installation and
host-deploy Gate B / HTTPS Gate C remain separately executed and evidenced.

**Reviewed host-deploy consumer:** `04c1006742e7592f2ec5f2103c7874404fc361a8`
(PR #3 candidate, host-deploy 0.10.6)

This contract joins independently authenticated station authority with a
prepared certify-manage issuer and the local host-deploy nginx consumer without
letting any one producer select the whole certificate policy.

## Separate trust roots

Three existing records remain distinct:

1. `/etc/zog/host-install/certificate-assignment-authority.json`,
   root:root 0444 — independently authenticated Ed25519 station assignment
   signer pin.
2. `/state/host-discover-certificate-authority/authority.json`,
   root:root 0600 — host-discover's signed assignment checkpoint and first
   monotonic root history.
3. `/etc/zog/host-deploy/certificate-managed-binding.json`,
   root:root 0600 — the independently installed local consumer binding required
   by host-deploy PR #3.

host-install does not replace host-discover's checkpoint. It owns a second
monotonic state:

`/state/host-install/certificate-owner-authority/`

containing root:root 0600 `ledger.json`, `authority.json`,
`transaction.json` while a publication is incomplete, and a persistent lock.

The public owner receipt is
`/state/host-install/certificate-owner-authority/authority.json` and is the
path supplied to host-deploy's `--owner-authority` gate.

## Independently installing the signer pin

The installer accepts a pin only with a separately authenticated expected
fingerprint:

```sh
sudo host-install certificate-authority-pin-install \
  --pin /root/reviewed-station-authority.json \
  --expected-key-id <64-hex-ed25519-fingerprint>
```

The command verifies the Ed25519 public key/fingerprint, requires the pin's
registry to equal the live installation's control registry, and uses
no-replacement root publication. Repeating the exact pin is idempotent; a
different key or registry conflicts.

This command does not approve a Host or retrieve a key from the station. The
pin file and expected fingerprint must come from the independent station
authority ceremony.

## Independent local consumer/credential intent

The local installer records only non-secret intent:

```json
{
  "schema": "zog-host-install-certificate-owner-intent-v1",
  "service_id": "candidate-nginx",
  "dns_mode": "local-cloudflare",
  "dns_zone": "example.org",
  "credential_id": "local-cloudflare",
  "credential_revision": 3
}
```

Install with:

```sh
sudo host-install certificate-owner-intent-install --intent /root/owner-intent.json
```

For HTTP-01, `dns_mode`, `dns_zone`, `credential_id` and
`credential_revision` are null. DNS-01 supports the reviewed
`local-cloudflare` or `command-center-broker` modes. No API token, password,
private key or other credential bytes are stored in this record.

## Prepared issuer and local binding

`certificate-owner-reconcile` requires the existing certify-manage native
preparation to be terminal and independently attested:

- exact immutable software view;
- root-control execution grant;
- issuer UID/GID;
- persistent certificate-data storage ID/path;
- root-control identity agreement;
- installed box-control/root-control bytes and wheel RECORD.

It separately reads the protected
`/etc/zog/certify-policy/policy.json` through certify-manage's trusted-policy
reader and derives the canonical certificate ID, hostnames, contact email,
ACME directory, challenge and `policy_sha256`.

The local host-deploy delivery policy must independently agree with that issuer
state and policy:

- `service_id` equals the installed local intent;
- certificate ID and hostnames equal certify-manage policy;
- `policy_sha256` equals certify-manage's authorization fingerprint;
- issuer UID and peer UID equal the prepared issuer UID;
- issuer-state path equals the prepared certificate-data path.

The resulting
`zog-host-deploy-managed-certificate-consumer-binding-v1` joins those local
facts with the live installation/STATE IDs and independently installed signer
pin. The original signed station assignment must match all signer-controlled
fields, while it cannot choose `service_id` or `policy_sha256`.

## Exact host-deploy source / installed-byte gate

host-install pins the reviewed PR #3 modules:

- `certificate_managed_authority.py`:
  `d9e6cc0efac7b42503e887cea44f308a7f58ebda`
- `certificate_hostname_authority.py`:
  `fc833cb3164e018076e2cc4a4a75aa12923c4c8d`
- `certificate_delivery.py`:
  `d857e426ab84d6f103e29c36d9d6bba0c4c403f3`

Before reconciliation, the installed `host-deploy` 0.10.6 distribution (or an
explicit aggregate `zog` distribution) is checked against those Git blobs and
its wheel RECORD. Reconciliation then calls the reviewed host-deploy owner
validators/managed derivation rather than inventing a parallel delivery
schema.

## Reconciliation command

After the station signer pin, host-discover root checkpoint, prepared issuer,
local owner intent and protected delivery policy all exist:

```sh
sudo env -u PYTHONPATH -u PYTHONHOME \
  /opt/zog-state-test/venv/bin/host-install certificate-owner-reconcile \
  --controller-project /path/to/controller/project \
  --root-control-socket /run/zog/root-control.sock \
  --software-view sha256:<exact-view> \
  --delivery-policy /etc/zog/host-deploy/certificate-delivery.json \
  --python-executable /opt/zog-state-test/venv/bin/python \
  --host-deploy-distribution host-deploy
```

The exact delivery-policy path is deployment-specific but must be root-owned
and pass the reviewed host-deploy validator. The command itself never contacts
ACME, DNS or nginx.

## Second monotonic ledger and crash fencing

The installer ledger freezes:

- installation/STATE/registry/signer identity;
- local binding digest;
- delivery-policy digest;
- local intent digest, including credential revision;
- issuer storage/grant/UID/GID/software-view identity;
- controller installed-RECORD digest;
- highest accepted signed assignment revision/operation/digest;
- owner receipt digest and terminal revocation state.

A normal higher signed authority revision may advance the ledger only when all
local and issuer bindings remain identical. A lower revision, reused operation,
same-revision content conflict, changed credential revision, changed service or
policy hash, changed issuer storage/grant, or reversal after revocation blocks
and requires an explicit future migration contract.

Publication ordering is:

1. install/verify the immutable local binding;
2. write the pending transaction;
3. fsync and atomically advance the monotonic ledger;
4. atomically publish the owner receipt;
5. re-read the current host-discover root checkpoint;
6. clear the pending transaction only if the exact
   revision/operation/assignment digest still matches.

If interruption occurs after the ledger advances but before the owner receipt
is replaced, reconciliation resumes only when the retained transaction exactly
matches that ledger. Missing or conflicting recovery evidence blocks.

If host-discover advances concurrently, the old owner receipt is not treated as
current: host-deploy itself reopens the signed root checkpoint on every managed
delivery request, and host-install leaves recovery evidence for another
reconciliation.

Read-only status is available with:

```sh
sudo host-install certificate-owner-inspect
```

## Native handoff boundary

Once the second owner ledger is retained, `certificate-native-observe` compares
it with the same prepared issuer grant/storage, root signed assignment and
selected certify-manage inspection. It can mark
`host_deploy_native_gate_handoff_ready=true` only when all those claims agree
and a genuine selected inspect result is present.

That flag is a handoff to host-deploy Work, not HTTPS activation.

Host-deploy Work still owns:

- native Gate B with authentic SO_PEERCRED and current root authority;
- renew → selected inspect → stage correlation;
- certificate delivery and exact nginx configuration test/reload;
- rollback/uncertainty handling;
- localhost SNI/CA/hostname/fingerprint validation;
- reboot and concurrent revocation tests;
- explicitly authorized staging-FQDN HTTPS Gate C.

No source or installer success here authorizes public CA issuance, Cloudflare
token creation, DNS mutation, production ports 80/443, unattended renewal, or
production nginx changes.
