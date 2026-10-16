# Protected station application-progress observer deployment

**Status:** host-install 0.8.0 source/deployment-profile implementation. Native
systemd/socket acceptance remains a separate disposable-host gate.

This profile implements the host-install side of the station-access
`zog-application-progress-v1` handoff. It deploys the root-owned systemd
socket/service definitions needed to run box-control's read-only
`application_progress_broker`, and it binds the station consumer to the
**numeric execution UID from its protected application grant**.

It does not infer or authorize an account from a username.

## Identity model

The deployment owner supplies four numeric values obtained from authoritative
protected execution/controller evidence:

- station-access web runtime UID;
- station-access web runtime GID;
- controller project-owner UID;
- controller project-owner GID.

The station UID and controller UID must be distinct and non-root. host-install
does not call NSS to translate `station-access`, `host-welcome`, `regular`,
or any other account name. In particular, the historical UID 993 mentioned in
station-access migration documentation is **not** a default.

The generated socket uses:

```text
SocketUser=<station-runtime-uid>
SocketGroup=<station-runtime-gid>
SocketMode=0600
```

and the generated broker service uses:

```text
User=<controller-owner-uid>
Group=<controller-owner-gid>
... application_progress_broker
    --project <fixed-controller-project>
    --authorized-uid <station-runtime-uid>
    --root-control-socket /run/zog/root-control.sock
```

Thus DAC and `SO_PEERCRED` authorize the same station runtime identity, while
the server runs under the separately bound controller identity.

## Socket visibility inside the isolated application

A box-control application root does not automatically inherit the host's
`/run`. The host listener therefore lives at:

`/run/zog-host-export/application-progress/application-progress.sock`

which is within box-control's existing administrator-approved host-export root.
The profile merges this exact protected capability into the supplied canonical
`/etc/zog/host-bindings.json` policy:

- project: the exact controller project path;
- application: `station-access`;
- program: `web`;
- capability: `application-progress`;
- source: `/run/zog-host-export/application-progress`.

box-control projects that capability read-only at
`/run/zog-host/application-progress` inside the application. The station
consumer therefore uses:

`/run/zog-host/application-progress/application-progress.sock`.

The source policy is an explicit input to staging. host-install preserves all
existing entries, adds the one exact capability idempotently, and refuses a
conflicting existing capability rather than replacing unrelated policy.

## Station settings emitted by the profile

`profile.json` records the reviewed values that the station deployment owner
must inject into the station application configuration:

```text
STATION_ACCESS_APPLICATION_PROGRESS_ENABLED=1
STATION_ACCESS_APPLICATION_PROGRESS_SOCKET=/run/zog-host/application-progress/application-progress.sock
STATION_ACCESS_APPLICATION_PROGRESS_CONTROLLER_UID=<controller-owner-uid>
```

These are installation outputs, not browser-selectable values. This host-install
profile does not rewrite station-access's immutable application declaration or
silently restart the station runtime.

## Staging command

The source command is:

```sh
host-install application-progress-stage \
  --output /path/to/new-overlay \
  --controller-project /absolute/controller/project \
  --station-consumer-uid <uid-from-protected-station-grant> \
  --station-consumer-gid <gid-from-protected-station-grant> \
  --controller-owner-uid <numeric-controller-owner-uid> \
  --controller-owner-gid <numeric-controller-owner-gid> \
  --host-bindings-policy /trusted/current/host-bindings.json
```

The output contains:

- `etc/systemd/system/zog-application-progress.socket`;
- `etc/systemd/system/zog-application-progress.service`;
- merged `etc/zog/host-bindings.json`;
- root-owned `profile.json` containing the exact UIDs, paths, source pin and
  station settings.

The manifest marks the socket for enablement and the service as socket-activated.
The staging command itself does **not** call systemctl, start a service, mutate
STATE, change a protected execution grant, or restart station-access.

The broker contract is pinned to box-control source
`03c847ec6adc55fd5e2268534d47b500d9f52ab9`. Final installation must bind the
aggregate `zog` Python software to a reviewed box-control revision containing
that broker contract; the manifest pin is not a substitute for installed-byte
verification.

## Authority exclusions

This observer is read-only. Deployment grants no authority to:

- submit, retry, cancel or resume a build;
- launch or replace an application;
- start greetd or another login manager;
- promote a host generation;
- reboot the host;
- expose controller argv, environment, logs or credentials.

A missing socket, wrong UID, unavailable root-control observation, stale response
or bad controller evidence remains unavailable/unknown to station-access.

## Acceptance boundary

Source tests verify numeric identity rendering, preservation/conflict handling of
the existing host-binding policy, fixed socket paths, station settings, no
hardcoded consumer username, and staging-only behavior. The standard host-install
wheel/sdist audit also checks these templates are packaged.

Native acceptance still must verify on a disposable host:

1. the actual station protected grant UID/GID equals the rendered socket owner and
   broker authorized UID;
2. the broker process actually runs under the recorded controller owner UID/GID;
3. socket ancestry, mode and any SELinux label are correct;
4. the read-only host capability is visible only in the station `web` runtime;
5. a wrong UID cannot connect and the correct station runtime can;
6. the client authenticates the server's controller UID;
7. reboot preserves the intended identities and stale/pruned observations remain
   unknown rather than successful.

No production cutover is implied by the source profile.
