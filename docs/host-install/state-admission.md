# Local installer observation protocol v1

Host-install 0.4 supplies the producer half of narrow identity admission. The
consumer obtains a fresh protected-ledger observation, then independently checks
an existing identity using host-identify. Successful observation never permits
enrollment, signing, archive renewal or command execution.

## Public consumer API

`zog.host_install.state_admission.request_live(context)` accepts the consumer's retained
`state_inspect.inspect_live()` context. Run as host-discover UID/GID 970 after the
consumer's live STATE inspection and write probe. This function contacts the fixed
local socket, authenticates its root peer, generates a fresh 256-bit nonce,
validates the response and rechecks the consumer's retained STATE.

It returns an observation containing:

- `status`: `consumption-observed` or `recovery-required`.
- `recovery_hold`: a boolean; any final or pending protected hold means true,
  including an unreadable/corrupt hold's presence. Unavailable inspection is an
  error, never false.
- `receipt`: the protected consumed host-identify receipt, or null when held.
- `bindings`: current Linux boot ID, bootstrap and marker canonical SHA-256,
  retained STATE device major:minor and root inode.
- `identity_action`: `verify-existing` or `block`.
- `control_authorized: false` and `transport_enabled: false`.

Do not feed saved JSON, the older runtime projection, or CLI output into an
adapter as authoritative evidence. `validate_response` and `observe` are internal
helpers for the authenticated implementation and tests; they authenticate no
caller-supplied object by themselves. The caller is trusted in-process code.

The consumer must refuse on exceptions, holds, missing receipts or identity-load
failure. Use host-identify's descriptor-anchored load-existing API on the retained
STATE identity directory; never call prepare or a legacy create-on-missing loader.
Recheck STATE after loading. Compare expected fingerprint and independently verify
any expected registry UUID binding. A fingerprint does not prove UUID agreement.
Take another fresh observation after identity loading and require the same receipt
and no hold; discard the attempt on any change or failure. Do not combine cached
hold and consumption values from separate admission attempts.

An observation is a point-in-time read, not a lease or a continuous fault monitor.
The consumer owns process-lifetime fault latching and future rechecks. A hold can
be introduced after a successful response; this protocol alone cannot authorize
ongoing operations. Missing/corrupt keys are discovered by consumer load-existing,
not by the producer, which deliberately never reads private keys. The root
initialization coordinator retains responsibility for its durable recovery holds.
There is no hold reset or remote recovery operation here.

## Protected producer behavior

The producer repeats live mount/account/layout verification. It opens the existing
root-private operations directory and obtains a nonblocking shared lock on the
existing installer lock; it never creates or repairs that lock. An in-progress
exclusive installer operation refuses the query. It checks protected hold names,
matching root authorization, and completed consumption. Missing, corrupt, unsafe
or partially published records refuse; a pending consumption publication must be
reconciled through the existing root coordinator. Neither fresh mode nor a marker
alone is enough. Migration/recovery modes cannot produce an unheld observation.

The response binds to the producer's inspected configuration and actual STATE
filesystem. The client compares those bindings with its own retained descriptor.
A different device, boot or configuration refuses even if a path name matches.
No source path, action, key path, reset request or external evidence is accepted
from the client. No private key is returned or read by this service.

## Installation and wire format

Install the two reviewed templates under `examples/systemd/`:
`host-install-admission.socket` and `host-install-admission@.service`. Enable the
socket only after explicit STATE preparation, authorization and successful identity
consumption. Review the installed ExecStart path. The units depend on STATE;
the socket requires the identity coordinator. It uses `DefaultDependencies=no`
with explicit sysinit and shutdown ordering because admission follows normal
bootstrap services. The default socket ordering before sockets.target would form
a cycle through basic.target and the identity coordinator. Mount loss stops the socket and
active request services. The templates are not automatically installed by the CLI.

The listener is `/run/host-install/admission.sock`, root:host-discover 0660,
under root:root 0755 `/run/host-install`. It uses systemd `Accept=yes` with one
root process per connection. The service is `host-install state-admission-serve`,
with its connected socket as stdin/stdout and diagnostics in journald. The server
requires kernel `SO_PEERCRED` UID 970; the client requires peer UID 0 and validates
the socket type, parent ownership and socket ownership/mode. Membership in archive
or host-control groups does not grant access. There is no TCP listener.

One canonical JSON request is sent, then the client shuts down its write side:

```json
{"kind":"zog-host-admission-request","nonce":"64-lowercase-hex-characters","schema":1}
```

The nonce placeholder above describes the format; it is not a valid sample nonce.
The response has `schema: 1`, `kind: zog-host-admission-response`, the matching
`nonce`, and either `ok: true, observation: {...}` or `ok: false, code: ...`.
The server closes the connection after one response. Unknown fields/versions and
oversized input refuse. Limits: 4096 request bytes, 65536 response bytes, five
seconds per socket operation; the service has a ten-second total runtime limit.
The socket limits concurrent services to four. Client failures are terminal for
that admission attempt; no legacy transport fallback is permitted.

## Schema and capability ownership

This protocol declares only its own schema. It does not report identity, trust,
control or box-control state compatibility on another program's behalf. The
installer's expected schema values are not runtime declarations. Host-discover
must keep its wider policy blocked until the respective components supply their
actual capabilities. A narrow diagnostic can report successful existing-identity
verification while keeping managed transport and remote control disabled.

## Acceptance boundary

Required local tests cover protected ledger reads, shared/exclusive locking,
missing/partial/corrupt records, hold presence, socket protocol bounds, peer
rejection, nonce/configuration/boot/device binding and consumer mount recheck.
The existing suite exercises real host-identify persistence and restart behavior.
The Work container restricts pathname socket creation and maps only UID 0; its
client/server tests use real socketpairs with explicit ownership/account and
connect substitutions. Synthetic systemd verification is syntax validation only.

Before enabling this endpoint with a managed consumer, test the actual socket
activation, root-to-UID-970 connection, mount loss, unavailable producer and
consumer's load-existing path together on a disposable Linux host. The earlier
AWS STATE test predates this protocol and does not establish that acceptance.

Joint AWS acceptance on 2026-10-02 validated this corrected template with
host-discover 0.4.0 and host-identify 0.3.3, including actual socket activation,
service accounts, reboot and refusal cases. See the
acceptance record (historical, retained privately; not a public acceptance claim).
That result covers narrow identity verification only.
