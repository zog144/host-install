# Console-first bootstrap readiness

Status: **host-install 0.7.0 source contract and synthetic acceptance**.

This contract implements the host-install portion of the console-first
host-welcome handoff. It deliberately does **not** install or launch greetd, X11,
Wayland, Firefox, Chromium, i3, TurboVNC, station-access, box-control or
root-control. Those remain separately authorized post-install application/runtime
concerns.

## Boot ordering

The earliest host-install-owned welcome surface is the socket-activated sanitized
readiness producer:

- `host-install-welcome.socket` may start after `sysinit.target`;
- it does **not** require or order after `state.mount`, host identity,
  `network-online.target`, box-control, root-control, a browser, greetd or any
  graphical stack;
- an early request before STATE is inspectable returns `unknown`, never an
  invented success;
- the accepted request handler is bounded by a six-second systemd runtime limit
  and a three-second protocol timeout;
- enabling the socket adds only a normal `Wants` relationship through
  `WantedBy=multi-user.target`; failure of the socket cannot make
  `multi-user.target`, getty or emergency login require it.

Normal getty/login owns the TTY. The producer units contain no `TTYPath`,
`StandardInput=tty`, `Before=getty...`, `Requires=getty...` or
`Conflicts=getty...` directives. They do not replace a login prompt.

A future automatic text host-welcome consumer should likewise be best-effort and
bounded: it may want/after the readiness socket, but must not become a prerequisite
of getty, emergency.target, STATE, controller bootstrap or networking. A
foreground interactive welcome that accepts input belongs **after an ordinary
authenticated login** unless a separately reviewed login/session boundary owns
that input. host-install does not ship such a login manager.

## Protected producer and peer model

The producer runs as root because the existing STATE inspection and protected
identity-consumption ledger require privileged reads. The consumer is a separate
local OS account named `host-welcome`.

This account is intentionally **not** added to `zog-host-accounts-v1`:

- changing that protected profile would turn a presentation feature into a STATE
  schema migration;
- the account must have a unique non-root UID/GID;
- it must use a nologin shell;
- it must not reuse the protected host-discover/box-control UIDs or groups;
- it must have no supplementary groups.

The account can therefore be provisioned by the base-host/account owner without
granting protected STATE membership. If it is absent, the socket cannot be
started, but login/getty remains unaffected.

The Unix socket is fixed at `/run/host-install/welcome.sock`, owned
`root:host-welcome` mode `0660`. The server verifies kernel
`SO_PEERCRED` against the dedicated account. The client checks the root-owned
peer, socket type/ownership/mode, response nonce, current boot ID and freshness.
There is no TCP listener, caller-selected path, action selector or detached JSON
live-authority path.

The root producer may read protected evidence, but the snapshot strips:

- identity receipts and fingerprints;
- private-key or credential material;
- STATE device/inode/PARTUUID/filesystem UUID;
- registry/control-authority configuration;
- source paths, command arguments and application logs.

## Producer schema

The live response contains one
`zog-host-install-bootstrap-readiness-v1` snapshot.

It reports separate fields for:

- `installation` — validated protected installation record;
- `state_integrity` — current live STATE inspection;
- `host_identity` — completed protected identity-consumption observation only;
- `recovery` — clear vs protected recovery hold;
- `boot_generation` — selected and actually observed boot slot/generation,
  without changing either;
- `headless_installation` — aggregate core bootstrap readiness, independent of
  optional graphics;
- `optional_applications` — fixed non-authority flags;
- `observation_dependencies` — records that this observer does not need
  networking, controller availability or a browser;
- `capabilities` — fixed false mutation/secret/control capabilities.

A missing/not-yet-mounted STATE becomes `unknown`. Structurally invalid or
mismatched protected STATE becomes `failed`. Missing identity consumption
becomes `pending`. A recovery hold becomes `failed/recovery-required`.

A verified installation record is intentionally distinct from verified identity
integrity and from the active boot generation. host-install does not turn one
green row into another.

## Optional applications and progress

The producer is **not** an application-progress producer. It does not synthesize
`zog-application-progress-v1`, infer build percentages, inspect compiler jobs or
authorize an application because a status page was rendered.

Every snapshot fixes these properties:

- `progress_authoritative=false`;
- `download_authorized=false`;
- `launch_authorized=false`;
- `generation_promotion_authorized=false`;
- `login_manager_start_authorized=false`;
- `reboot_authorized=false`;
- `graphics_required_for_headless_success=false`.

Application progress must come from the authenticated image-build/controller
owners described by the coordinated handoff.

## First-boot graphical handoff

`zog.host_install.welcome_readiness.graphical_handoff()` is a pure policy
check for the later boundary. It accepts only closed evidence for:

1. an explicit graphical-session request;
2. a verified immutable application software ID;
3. an authorized controller request ID;
4. a verified local-session security capability ID.

Only when all four are present does it report
`eligible-for-authorized-supervisor-request`. Even then:

- `host_install_authorizes_launch=false`;
- `auto_start=false`;
- `auto_reboot=false`;
- installation success does not depend on graphics.

The authorized supervisor/controller still owns any actual launch.

## Synthetic acceptance fixtures

`examples/welcome-bootstrap-v1/scenarios.json` records the source-level fault
matrix:

- offline reboot before STATE is visible;
- unavailable controller;
- malformed protected STATE;
- incomplete identity initialization;
- stale/prior-boot observation;
- delayed network;
- no browser;
- foreground console requiring login ownership;
- recovery hold.

All fixtures require zero persistent writes. Tests also verify the units have no
TTY takeover or optional-stack ordering, a corrupt STATE never becomes green,
identity-pending remains distinct from installation-record validity, stale/old
boot responses are rejected, recovery remains read-only, and headless success
does not require graphics.

This is source/synthetic acceptance only. Native boot/getty interaction and a
real `host-welcome` account/socket consumer on a disposable Zog host remain a
separate host-deploy acceptance gate.
