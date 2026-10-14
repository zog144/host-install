# host-install public source and dependency notices

The first-party host-install code, documentation, synthetic example records,
test fixtures and service-unit templates in this reviewed public repository
are available at your option under `BSD-3-Clause OR GPL-3.0-only`.
See [LICENSE](LICENSE) and the complete terms under [LICENSES](LICENSES/).

host-install consumes separate interfaces from image-build, host-identify
and host-discover. Those components and their dependencies are not bundled
or relicensed by the host-install public-source grant. The project does
not vendor a Linux distribution, kernel, systemd, firmware, filesystem tools
or AWS provider packages. Each installed third-party tool retains its terms.

Setuptools, pytest and optional build/test filesystem utilities are obtained
separately. The sample configurations, UUIDs, mount layouts and test fixtures
are non-production examples; they do not grant authorization to erase a disk,
provision a cloud host or deploy managed identities.

The new public Git history omits the prior private commits/tags, the old
private no-grant notice, private handoff metadata and dated AWS test scripts.
Historical operational results are kept separately with their original
identities and must not be represented as acceptance of the new public commit.
Python publication continues through the aggregate `zog` distribution.
