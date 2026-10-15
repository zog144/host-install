# Certificate application enablement contract

Status: **host-install 0.6.0 contract + simulated durable lifecycle**. This does not issue a
certificate, authenticate controller evidence, expose a proxy, publish a key, or
change an archive role.

The certificate application remains a separate core application. host-install
owns only the fail-closed ordering decision over evidence already authenticated
by the appropriate host owner.

## Required order

The evaluator requires these boundaries in order:

1. canonical STATE is verified and not under recovery hold;
2. the controller-issued `certify-manage` application grant is verified;
3. the selected immutable software generation is verified;
4. the protected host-owner certificate policy contains an operator-approved
   hostname and an explicitly chosen `http-01` or `dns-01` challenge;
5. the durable certificate application state is available and one-time
   application preparation has completed;
6. authorized certificate issuance/renewal completes and the resulting local
   certificate is independently inspected;
7. host-deploy performs its separately authorized versioned publication;
8. external HTTPS presentation is independently verified.

A local SAN/expiry/key check is therefore insufficient for HTTPS readiness.

## Durable identity rule

The application persistent state is outside disposable HOST generations. If it
contains an existing ACME identity, the evaluator reports
`identity_action: preserve-existing` across reboot or immutable generation
replacement. Evidence that an existing identity is being replaced is blocked
with `acme-identity-regeneration-forbidden`.

host-install never deletes, resets, regenerates, backs up, restores, or reads ACME
account keys itself. The application controller owns the durable mount and
`certify-manage` owns its private state format. First boot must not treat an
already-populated durable mount as permission to create a new ACME identity.

No certificate, ACME account, DNS token, hostname credential, or other secret is
stored in an installation image or accepted by this evaluator.

## Missing operator policy

Missing or incomplete hostname/challenge authority produces the exact status:

`awaiting-operator-approved-hostname-challenge`

The evaluator does not infer a hostname from DHCP, DNS, station identity,
controller addresses, reverse DNS, or any archive endpoint. It never falls back
to a self-signed certificate or an automatic public ACME request.

## Headless status

A non-browser management path is available for detached, already-authenticated
secret-free evidence:

```sh
host-install certificate-status certificate-evidence.json
```

This command is a pure status evaluator. Supplying a JSON file to it grants no
authority and performs no mutation. The closed evidence schema intentionally
contains approval booleans/statuses and opaque grant/generation identifiers, not
the approved hostname itself, certificate PEM, account keys, provider tokens, or
Certbot command arguments.

The output reports the next lifecycle boundary and fixed safety properties.
`self_signed_allowed`, `public_auto_issuance_allowed`,
`proxy_exposure_allowed`, and `archive_role_change_allowed` are always false.
The station observer mTLS identity is explicitly reported as a separate
certificate role.

## Failure behavior

Failed or uncertain preparation/issuance, unavailable durable state, conflicting
lineage evidence, publication failure/rollback, and external verification failure
all block forward progress. No failure state permits:

- self-signed fallback;
- automatic public issuance;
- nginx/proxy exposure;
- archive-role or lease changes;
- replacement of an existing ACME identity.

An uncertain issuance or lineage requires operator reconciliation rather than a
blind retry.

## Ownership boundaries

`certify-manage` owns ACME policy enforcement, account/lineage operations and
issuer-private staging. The application controller owns the dedicated persistent
mount and execution grant. `host-deploy` owns authorized certificate transfer,
consumer binding, nginx validation/reload/rollback, and external HTTPS
verification. host-install reflects those boundaries but does not inherit their
privileges.


## Simulated durable lifecycle

Version 0.6.0 adds a secret-free lifecycle record that can be exercised before
image-build deployment is available. The record persists only opaque coordination
facts: the bound certificate-state identity, the completed application preparation
revision, whether an ACME account and certificate lineage have previously been
observed, the first/last immutable software generation, and the last lifecycle
status. It contains no hostname, ACME directory, certificate PEM, private key,
DNS credential, provider identifier, or Certbot argument.

A simulated observation names whether the certify-manage application is available
and, when available, supplies its persistent-state identity and preparation
revision plus the already-authenticated certificate evidence consumed by the
0.5.0 gate. Tests exercise installation, temporary application unavailability,
reboot, immutable software upgrade, and recovery of the same durable application
state.

Use the source-only simulation command:

```sh
host-install certificate-lifecycle-simulate observation.json \
  --record /tmp/certificate-lifecycle.json
```

The record is mode 0600 and replaced atomically with stale-writer detection. This
is a development/acceptance surface, not a production controller API and not an
authorization to invoke certify-manage.

Once a preparation revision is durably observed complete, reboot or a HOST
generation change does not reset it. A new preparation revision is reported as
`certificate-preparation-migration-required` rather than being run
automatically. Likewise, a different persistent-state identity, disappearance of
an ACME account that was previously present, or disappearance of a previously
healthy certificate lineage requires operator reconciliation.

An ACME account may validly exist before the first certificate lineage. That state
is preserved and does not trigger regeneration.

## Local and command-center intent transitions

The policy status layer now distinguishes missing configuration from hard
authority failures. Missing policy remains
`awaiting-operator-approved-hostname-challenge`. Revoked, conflicting or
migration-required policy is blocked and cannot fall back to another hostname,
provider, self-signed certificate or public automatic issuance. This lets a
future trusted adapter map either local-admin or command-center ownership into
the same lifecycle without host-install learning DNS credentials or choosing an
FQDN.
