# Non-resident installation and STATE contract

`host-install` supports a **non-resident** installation mode for bringing Zog
services onto an existing Linux host while leaving that host's operating system,
boot chain and root filesystem externally managed.

This mode exists to support native integration before a complete resident Zog
bootable host is available. It does **not** create a resident HOST-A/HOST-B slot,
does not claim Secure Boot, measured boot or remote attestation, and does not
make Zog responsible for keeping the underlying Linux management path bootable.

## Record compatibility

The existing STATE layout and bootstrap profile remain `state-contract-v1`.
Installation records now have two accepted forms:

- schema 1: legacy **resident** records only. Their existing fields and HOST slot
  checks are unchanged.
- schema 2: explicitly carries `installation_mode`, currently `resident` or
  `non-resident`.

A schema-2 non-resident record has no `expected_artifact_id`,
`expected_host_generation`, `expected_slot`, `root_partuuid`, `host_slots` or
`foreign_boot_bundle`. Its `installer_recorded.host_os` must be exactly:

```json
{
  "management": "externally-managed",
  "boot": "externally-managed",
  "root_filesystem": "externally-managed"
}
```

The lifecycle operation remains separate from installation ownership.
`fresh`, `upgrade`, `reinstall`, `migration` and `recovery` describe the
installation transaction; `resident` / `non-resident` describes who owns the
host OS. Upgrade and reinstall must preserve that ownership mode. Changing it is
a separate migration problem and is rejected by the ordinary transition path.

Unknown installation schemas and modes fail closed. Legacy schema-1 resident
validation is not relaxed.

## STATE invariants reused unchanged

Non-resident mode reuses the canonical `/state` security boundary:

- one ext4 filesystem mounted exactly at `/state`;
- exact PARTUUID, filesystem UUID and STATE volume UUID bindings;
- STATE must not share the current host root device;
- the mount and superblock must both be writable;
- nested mounts below `/state` are rejected;
- fixed account assignments and collision checks remain unchanged;
- first identity initialization still requires the explicit installer
  transaction authorization;
- recovery holds and interrupted initialization semantics are unchanged.

Mounting or formatting a STATE filesystem never authorizes creation of a host
identity.

## Plan-only CLI

The source tree contains
`examples/non-resident-state-v1/bundle.json`, a schema-2 non-resident example.

Validate it with:

```sh
python3 -m zog.host_install state-validate \
  examples/non-resident-state-v1/bundle.json
```

Project it into the machine-readable installation contract with:

```sh
python3 -m zog.host_install non-resident-plan \
  examples/non-resident-state-v1/bundle.json
```

The committed expected projection is
`examples/non-resident-state-v1/disposable-host-plan.json`.

The plan is deliberately non-authoritative. It records
`device_writes_authorized=false`, `formatting_authorized=false` and
`identity_initialization_authorized=false`. It names the stable
`/dev/disk/by-partuuid/...` mount reference and the required root-owned
configuration file ownership/modes, but does not inspect or mutate a block
device.

## systemd ownership and failure behavior

The non-resident plan retains `state.mount` as the mount unit for `/state`.
Rendered configuration must be root-owned and bind the exact PARTUUID.

Zog services that require STATE use:

- `Requires=state.mount`
- `After=state.mount`
- `BindsTo=state.mount`

An absent, wrong or read-only STATE therefore prevents those Zog services from
becoming ready. The external host OS management path must **not** acquire a
`Requires=` dependency on `state.mount`; failure of Zog STATE is not permission
to make the externally managed host unbootable or inaccessible.

The existing preparation and identity units already carry the required
STATE ordering. Later service profiles must preserve the same boundary.

## Safe removal

Removing a non-resident Zog installation means disabling/removing Zog service
integration first. STATE is retained by default. Deleting, reformatting or
otherwise destroying the STATE filesystem requires a distinct, explicit
operation and is not implied by uninstalling services.

This is important because STATE may contain durable host identity, trust,
controller history, certificate application state and recovery evidence.

## What remains for physical STATE provisioning

This source contract does not yet format or partition a live block device.
The next implementation stage must add an inspect/plan/apply workflow for a
dedicated volume that:

1. binds an explicitly selected cloud volume to the currently observed block
   device using stable identity evidence rather than a mutable `/dev` name;
2. refuses the running root disk, mounted/in-use devices, existing unexpected
   signatures and populated media;
3. requires explicit fresh-volume formatting authority;
4. records partition/format/mount/publication progress durably so interruption
   cannot cause a second blind format;
5. verifies the actual writable `/state` mount before creating Zog directories
   or allowing identity initialization.

The first native target is a fresh disposable EC2 host with a separate EBS
volume, GPT STATE partition and ext4 filesystem. Cloud creation, formatting,
reboot and native execution are Work/host-deploy activities and require a
bounded authorized run; this document and the plan-only CLI grant none of those
permissions.

## Issuer integration relation

The native certify-manage issuer gate can use this non-resident mode once
physical STATE provisioning is available. A disposable installation must create
its own controller grant and certificate-data storage under its verified STATE;
controller records or issuer-private state from the shared compiler must not be
transplanted.

Resident Zog boot acceptance remains a separate milestone.
