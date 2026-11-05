# Protected graphical owner Python environment

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

The disabled Task C unit selects
`/opt/zog/graphical-owner/venv/bin/python3 -I`, not the host's default
`/usr/bin/python3`. The selected root-control distribution requires Python
3.11 or newer; Amazon Linux 2023 may retain Python 3.9 as its system Python.
Do not replace the system interpreter or install into an existing issuer,
station or gateway environment to satisfy this service.

Before installing the unit as a usable candidate, the native installer must:

- Select an independently reviewed Python build and record its version,
  resolved executable path and SHA256. A venv symlink does not itself pin the
  underlying interpreter; attest that target and its update policy too.
- Use a dedicated root-owned environment at the exact path above. Its parent
  directories, configuration, interpreter and installed modules must not be
  writable by the gateway. Disable system-site-packages and use no editable
  source installation or gateway-controlled `.pth` inputs.
- Install exact reviewed dependency artifacts and the selected root-control
  wheel, retaining artifact hashes and verifying installed RECORD entries.
  Record which distribution owns every selected module. Broad dependency
  ranges in component metadata are not an acceptance lockfile.
- Run version/import and installed-byte inspection with this exact isolated
  interpreter. Confirm imports resolve within the protected installation.
- Keep both service and socket disabled and inactive. Preserve the source's
  hard-disabled native admission flag. Installing executable bytes supplies
  neither operator approval nor an external checkpoint identity.

The unit-source validator only verifies selection of this path and rejects
additional `ExecStart` overrides. It does not create the environment, attest
its contents, validate native authority or grant SSM admission. Missing
original authority, external checkpoint binding, ledger mount, authenticated
gateway or separate restricted SSM credentials remain installation holds.
