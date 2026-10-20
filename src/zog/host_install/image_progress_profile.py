"""Protected deployment profile for host-welcome's image-build progress observer.

This module stages policy and systemd source only.  It never enables the unit,
starts image-build work, writes image-build state, or grants graphical readiness.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib
import importlib.metadata
from importlib.resources import files as resource_files
import io
import os
from pathlib import Path
import pwd
import re
import stat
import sys

from .state_contract import canonical, require
from .state_inspect import directory
from .state_io import ensure_directory, lock, publish
from .welcome_readiness import welcome_account


PROFILE_KIND = "zog-host-welcome-image-progress-observer-profile-v1"
POLICY_SCHEMA = "zog-host-welcome-image-progress-observer-v1"
POLICY_PATH = "/etc/zog/host-welcome-image-progress-observer.json"
SOCKET_PATH = "/run/host-welcome/image-progress.sock"
UNIT_SOCKET = "zog-host-welcome-image-progress.socket"
UNIT_SERVICE = "zog-host-welcome-image-progress.service"

IMAGE_BUILD_REPOSITORY = "zog144/image-build"
IMAGE_BUILD_COMMIT = "fcc12f3db959afe395b1adfb5b0b4dc1f16a3258"
HOST_WELCOME_CONSUMER_COMMIT = "6edb11140a44a10061e5308fab03a43d9008dbfc"
GRAPHICAL_APPLICATIONS = (
    "agreety",
    "chromium",
    "firefox",
    "firefox-esr",
    "greetd",
    "i3",
    "turbovnc",
    "weston",
    "xorg-server",
)

IMAGE_BUILD_SOURCE_PYTHON_BLOBS = {
    "src/zog/image_build/__init__.py": "c68542ed78126dbc188ba09767fd5a396a88dee5",
    "src/zog/image_build/__main__.py": "6398d040c160a239520e218ec8a40f943f7562b2",
    "src/zog/image_build/application_data_targets.py": "94b5e69dcbe5ad30c4e98787fc217910a38e074e",
    "src/zog/image_build/application_software.py": "736cffeb3e42811f93bebb50a0fa9c52e4a7b52b",
    "src/zog/image_build/application_views.py": "91c144628a9cb5293706fb1114a7063dd30d9291",
    "src/zog/image_build/archive_mirror.py": "ee7724da03da142a3661168047c7a6edb1e97351",
    "src/zog/image_build/artifact_observations.py": "5ca72fc4e3f04a921860ad99853c1981ecf7c188",
    "src/zog/image_build/artifacts.py": "90924aea055b9520c14c223b795d5dba5d2b60d4",
    "src/zog/image_build/automake_results.py": "612aee762799168fce8ee34d38e18bef76bebb1b",
    "src/zog/image_build/box_control_adapter.py": "33df8012315c168ba8976a1f5fa3d815ead6a08f",
    "src/zog/image_build/build_environment.py": "ec36032b2b2a76a8e671aea5d7cf49cc5d41c03d",
    "src/zog/image_build/build_views.py": "7581de78d0d70dbfa1a1f7a2e308cd43fd3bec1c",
    "src/zog/image_build/certify_manage_software.py": "ed69143e42d13db8e0165158af61c9d592394e7b",
    "src/zog/image_build/cleanup.py": "a7f1dd098d686e0ad719dc3b106d78e9b42f5982",
    "src/zog/image_build/compiler_environment.py": "574463475535131dccbe51a6977ad9d2dfc0b234",
    "src/zog/image_build/compiler_results.py": "39a1dd7794ad1dae504067a109dbef67f90fc24f",
    "src/zog/image_build/configuration.py": "7e7d5be32f6e38f92806423678794d6e03c0b454",
    "src/zog/image_build/dependency_composition.py": "33cd6cfbb3a5b4829b6e66b115b587fb1c6355d4",
    "src/zog/image_build/developer/__init__.py": "880c4baf20c4d012ae337fe93117e46962166f26",
    "src/zog/image_build/developer/catalogue.py": "078583ff7711b63f223df32201218037472917c2",
    "src/zog/image_build/developer/distribution.py": "5a097e9a4d7e80e275b20c49157eeeac98002701",
    "src/zog/image_build/developer/host.py": "ee38d8746f36d0e155f4a33fe295ffaaf86b060a",
    "src/zog/image_build/developer/seed_build.py": "ff764d48ec6b7165a1b5c941d29eb82f043a2c32",
    "src/zog/image_build/developer/seed.py": "6c906bd8977a8cc89aab64aa911d77de05ef9e9a",
    "src/zog/image_build/developer/source_packaging.py": "9ffc0a2b1c934578adc7d1a119205e679c7b684a",
    "src/zog/image_build/engine.py": "c65a948ae027850247dee6da8999f121ee3397a4",
    "src/zog/image_build/errors.py": "dc80cc8438eab55c5438172328ae778e914f506a",
    "src/zog/image_build/filesystem.py": "1f6c1fa8628118de5ec2e6c727fd6b725498a99f",
    "src/zog/image_build/final_compiler.py": "a6da2465e15bac34f8a8247272e4c50f47321a7e",
    "src/zog/image_build/final_math.py": "2e55e7fe286cc8e98c8d8e638d3fc9f7abc53233",
    "src/zog/image_build/generation_provenance.py": "b3ca249d4bd6878d942a20a55f92e5d5c0267ae7",
    "src/zog/image_build/glibc_final.py": "9d26bd0054e57ba656ef1bb1bc717a2e3df7af51",
    "src/zog/image_build/glibc_publish.py": "96aaedb4806e19d6a4b6944b030751689b732e99",
    "src/zog/image_build/glibc_tests.py": "45db3424ab07a27e458323e805041c6fc5c61c86",
    "src/zog/image_build/graphical_application_plan.py": "02615a20ceabad26c6026b8b8101a1323ad921c9",
    "src/zog/image_build/host_export.py": "695a3232919e458c29a9028b9318e7f79dfafc37",
    "src/zog/image_build/host_fixture.py": "20aad88a97b1223a08f476b6f4ed8afc76daf4ad",
    "src/zog/image_build/host_inventory.py": "a2acbf9d392f92d53cbce6de9d07c31b317eef74",
    "src/zog/image_build/host_labels.py": "0b06299ad3c6bf99e4f954aba6dbc075459c30d7",
    "src/zog/image_build/host_trust_assembly.py": "10a44986f091c825e7d072d5db081d626aae2a9a",
    "src/zog/image_build/host_trust.py": "607f799a912113db00d781c033703492f03dd211",
    "src/zog/image_build/immutable_objects.py": "93d669eee7fa6609c15156a3c92deb93aa554530",
    "src/zog/image_build/info_index.py": "e8a7e343ec92f7e18b98fd458f1c51c6022ee012",
    "src/zog/image_build/installed_verification.py": "0a4947d25cac73e3ff4fa692e5308d3a55889841",
    "src/zog/image_build/integration_observations.py": "c58fa76a93f1c6d94ceea24ff468eafddec58b79",
    "src/zog/image_build/licensing.py": "95a84991e992eea0817d3f89e08007489052c4e5",
    "src/zog/image_build/local_network.py": "f6558f51323993c629bd92a87cc848b518b87613",
    "src/zog/image_build/metadata.py": "79238579b11e87070886b2fd0125a186a94fd29e",
    "src/zog/image_build/native_stage.py": "a043a4102ce11ec5707695eace4d96d8120762f8",
    "src/zog/image_build/native_tools.py": "1f79d24406526d925cfa31a06e6f51beee7239de",
    "src/zog/image_build/native.py": "693fe46f61ab487ac6aaf935259d5a0247806558",
    "src/zog/image_build/observation_snapshots.py": "024b4ad428eef13520d146a9de61dd3b9858081d",
    "src/zog/image_build/pins.py": "0768e3f7f774822931ee25f461d8476e4d65c273",
    "src/zog/image_build/pipeline.py": "90c1e561056d474d19a0458f66da27b6aea1d5ea",
    "src/zog/image_build/post_install_progress_broker.py": "fc50a6f86b5e1ddc088dc5b33e443a516a0c9189",
    "src/zog/image_build/post_install_progress.py": "5c4e03e1f496b704935caabebfa7eca63188f89e",
    "src/zog/image_build/provenance.py": "c4e5500d6fe97588c08aa5b85e57501c1f6c668e",
    "src/zog/image_build/public_https.py": "b33130cf7b465bdfe6ea11a9b9415041c4805e7a",
    "src/zog/image_build/python_enrollment.py": "b83d08d4bb123ef4dd3d4212fc74d3961f13de7d",
    "src/zog/image_build/python_runtime.py": "53daf791df0b47e848619af7a8f0d1527bb3168f",
    "src/zog/image_build/recipe_snapshots.py": "1ec7602923c39655efb9de0a7bde0e7522447a28",
    "src/zog/image_build/remote_contract.py": "5da3af46b9c3bfcff2df83a9c3c45cda20015e23",
    "src/zog/image_build/remote_operations.py": "fbede5bff57eabce896808fa0203e89dc4ca3976",
    "src/zog/image_build/retained_compiler.py": "58102d114de9e058b24ea5374909c85c3fef1feb",
    "src/zog/image_build/rootfs_compatibility.py": "3adbef4cdcef29a89bdc309eab30aeb40be167e2",
    "src/zog/image_build/runner.py": "28f5c3becec728a9b7118bd767497c014c43f6a6",
    "src/zog/image_build/runtime_companion_smoke.py": "1a19db020020c187a3a4d7004a25bcc7c536111a",
    "src/zog/image_build/runtime_composition.py": "ae87d335f3c54c4b2177de5f6ad19c71e7b52c9a",
    "src/zog/image_build/runtime_facilities.py": "651f5ceb35f40aae5831ead08d97495575740dff",
    "src/zog/image_build/runtime_image.py": "629a9164f243b5029c7e893599f73537d8233662",
    "src/zog/image_build/runtime_preflight.py": "4313f51b4e318171e9c37927cf0bba3c9849848d",
    "src/zog/image_build/runtime_requirements.py": "5a546714ecfa3d59fce0e3aa8ca73848483388f3",
    "src/zog/image_build/source_acquisition.py": "147f49814fa07dd7cbc29a3b1583fee7419c605f",
    "src/zog/image_build/source_libraries.py": "312b579766e3a7af5b3ab3f0e2340bc28961921d",
    "src/zog/image_build/source_provenance.py": "e4779ae850dedc90f1deba0442616186b68109bd",
    "src/zog/image_build/sources.py": "ee7415e6342b55aaac9574237b0e288a1ef2fa03",
    "src/zog/image_build/stages.py": "7895344e0503c735c8e8b8daaec2eee5a16994ac",
    "src/zog/image_build/temporary.py": "8935c337bb28c59e84682b3d5ef04e31d6eece09",
    "src/zog/image_build/test_fixtures.py": "44f1f518a7b0420cfd4fa6b6e435aaafb29ad383",
    "src/zog/image_build/toolchain_contract.py": "a6fd36400abb653e9830278dc0560671d384f137",
    "src/zog/image_build/toolchain_remote.py": "58f2ddaa9c6d999179da3f042b066e814bd4f804",
    "src/zog/image_build/trace_records.py": "befb5a85a9aefc30d41603d8726f6baef4dd3272",
    "src/zog/image_build/verification_observations.py": "91fe5270ea2521f06b5da4432e6da230dae126fc",
    "src/zog/image_build/worker_contracts.py": "6896e73cc43177c705bf47aaaeae6c512aca7be2",
    "src/zog/image_build/worker.py": "0425393deecb271e412da2d90f8fce158880a789",
}
IMAGE_BUILD_MODULE_BLOBS = {
    "zog.image_build": "c68542ed78126dbc188ba09767fd5a396a88dee5",
    "zog.image_build.__main__": "6398d040c160a239520e218ec8a40f943f7562b2",
    "zog.image_build.application_data_targets": "94b5e69dcbe5ad30c4e98787fc217910a38e074e",
    "zog.image_build.application_software": "736cffeb3e42811f93bebb50a0fa9c52e4a7b52b",
    "zog.image_build.application_views": "91c144628a9cb5293706fb1114a7063dd30d9291",
    "zog.image_build.archive_mirror": "ee7724da03da142a3661168047c7a6edb1e97351",
    "zog.image_build.artifact_observations": "5ca72fc4e3f04a921860ad99853c1981ecf7c188",
    "zog.image_build.artifacts": "90924aea055b9520c14c223b795d5dba5d2b60d4",
    "zog.image_build.automake_results": "612aee762799168fce8ee34d38e18bef76bebb1b",
    "zog.image_build.box_control_adapter": "33df8012315c168ba8976a1f5fa3d815ead6a08f",
    "zog.image_build.build_environment": "ec36032b2b2a76a8e671aea5d7cf49cc5d41c03d",
    "zog.image_build.build_views": "7581de78d0d70dbfa1a1f7a2e308cd43fd3bec1c",
    "zog.image_build.certify_manage_software": "ed69143e42d13db8e0165158af61c9d592394e7b",
    "zog.image_build.cleanup": "a7f1dd098d686e0ad719dc3b106d78e9b42f5982",
    "zog.image_build.compiler_environment": "574463475535131dccbe51a6977ad9d2dfc0b234",
    "zog.image_build.compiler_results": "39a1dd7794ad1dae504067a109dbef67f90fc24f",
    "zog.image_build.configuration": "7e7d5be32f6e38f92806423678794d6e03c0b454",
    "zog.image_build.dependency_composition": "33cd6cfbb3a5b4829b6e66b115b587fb1c6355d4",
    "zog.image_build.developer": "880c4baf20c4d012ae337fe93117e46962166f26",
    "zog.image_build.developer.catalogue": "078583ff7711b63f223df32201218037472917c2",
    "zog.image_build.developer.distribution": "5a097e9a4d7e80e275b20c49157eeeac98002701",
    "zog.image_build.developer.host": "ee38d8746f36d0e155f4a33fe295ffaaf86b060a",
    "zog.image_build.developer.seed_build": "ff764d48ec6b7165a1b5c941d29eb82f043a2c32",
    "zog.image_build.developer.seed": "6c906bd8977a8cc89aab64aa911d77de05ef9e9a",
    "zog.image_build.developer.source_packaging": "9ffc0a2b1c934578adc7d1a119205e679c7b684a",
    "zog.image_build.engine": "c65a948ae027850247dee6da8999f121ee3397a4",
    "zog.image_build.errors": "dc80cc8438eab55c5438172328ae778e914f506a",
    "zog.image_build.filesystem": "1f6c1fa8628118de5ec2e6c727fd6b725498a99f",
    "zog.image_build.final_compiler": "a6da2465e15bac34f8a8247272e4c50f47321a7e",
    "zog.image_build.final_math": "2e55e7fe286cc8e98c8d8e638d3fc9f7abc53233",
    "zog.image_build.generation_provenance": "b3ca249d4bd6878d942a20a55f92e5d5c0267ae7",
    "zog.image_build.glibc_final": "9d26bd0054e57ba656ef1bb1bc717a2e3df7af51",
    "zog.image_build.glibc_publish": "96aaedb4806e19d6a4b6944b030751689b732e99",
    "zog.image_build.glibc_tests": "45db3424ab07a27e458323e805041c6fc5c61c86",
    "zog.image_build.graphical_application_plan": "02615a20ceabad26c6026b8b8101a1323ad921c9",
    "zog.image_build.host_export": "695a3232919e458c29a9028b9318e7f79dfafc37",
    "zog.image_build.host_fixture": "20aad88a97b1223a08f476b6f4ed8afc76daf4ad",
    "zog.image_build.host_inventory": "a2acbf9d392f92d53cbce6de9d07c31b317eef74",
    "zog.image_build.host_labels": "0b06299ad3c6bf99e4f954aba6dbc075459c30d7",
    "zog.image_build.host_trust_assembly": "10a44986f091c825e7d072d5db081d626aae2a9a",
    "zog.image_build.host_trust": "607f799a912113db00d781c033703492f03dd211",
    "zog.image_build.immutable_objects": "93d669eee7fa6609c15156a3c92deb93aa554530",
    "zog.image_build.info_index": "e8a7e343ec92f7e18b98fd458f1c51c6022ee012",
    "zog.image_build.installed_verification": "0a4947d25cac73e3ff4fa692e5308d3a55889841",
    "zog.image_build.integration_observations": "c58fa76a93f1c6d94ceea24ff468eafddec58b79",
    "zog.image_build.licensing": "95a84991e992eea0817d3f89e08007489052c4e5",
    "zog.image_build.local_network": "f6558f51323993c629bd92a87cc848b518b87613",
    "zog.image_build.metadata": "79238579b11e87070886b2fd0125a186a94fd29e",
    "zog.image_build.native_stage": "a043a4102ce11ec5707695eace4d96d8120762f8",
    "zog.image_build.native_tools": "1f79d24406526d925cfa31a06e6f51beee7239de",
    "zog.image_build.native": "693fe46f61ab487ac6aaf935259d5a0247806558",
    "zog.image_build.observation_snapshots": "024b4ad428eef13520d146a9de61dd3b9858081d",
    "zog.image_build.pins": "0768e3f7f774822931ee25f461d8476e4d65c273",
    "zog.image_build.pipeline": "90c1e561056d474d19a0458f66da27b6aea1d5ea",
    "zog.image_build.post_install_progress_broker": "fc50a6f86b5e1ddc088dc5b33e443a516a0c9189",
    "zog.image_build.post_install_progress": "5c4e03e1f496b704935caabebfa7eca63188f89e",
    "zog.image_build.provenance": "c4e5500d6fe97588c08aa5b85e57501c1f6c668e",
    "zog.image_build.public_https": "b33130cf7b465bdfe6ea11a9b9415041c4805e7a",
    "zog.image_build.python_enrollment": "b83d08d4bb123ef4dd3d4212fc74d3961f13de7d",
    "zog.image_build.python_runtime": "53daf791df0b47e848619af7a8f0d1527bb3168f",
    "zog.image_build.recipe_snapshots": "1ec7602923c39655efb9de0a7bde0e7522447a28",
    "zog.image_build.remote_contract": "5da3af46b9c3bfcff2df83a9c3c45cda20015e23",
    "zog.image_build.remote_operations": "fbede5bff57eabce896808fa0203e89dc4ca3976",
    "zog.image_build.retained_compiler": "58102d114de9e058b24ea5374909c85c3fef1feb",
    "zog.image_build.rootfs_compatibility": "3adbef4cdcef29a89bdc309eab30aeb40be167e2",
    "zog.image_build.runner": "28f5c3becec728a9b7118bd767497c014c43f6a6",
    "zog.image_build.runtime_companion_smoke": "1a19db020020c187a3a4d7004a25bcc7c536111a",
    "zog.image_build.runtime_composition": "ae87d335f3c54c4b2177de5f6ad19c71e7b52c9a",
    "zog.image_build.runtime_facilities": "651f5ceb35f40aae5831ead08d97495575740dff",
    "zog.image_build.runtime_image": "629a9164f243b5029c7e893599f73537d8233662",
    "zog.image_build.runtime_preflight": "4313f51b4e318171e9c37927cf0bba3c9849848d",
    "zog.image_build.runtime_requirements": "5a546714ecfa3d59fce0e3aa8ca73848483388f3",
    "zog.image_build.source_acquisition": "147f49814fa07dd7cbc29a3b1583fee7419c605f",
    "zog.image_build.source_libraries": "312b579766e3a7af5b3ab3f0e2340bc28961921d",
    "zog.image_build.source_provenance": "e4779ae850dedc90f1deba0442616186b68109bd",
    "zog.image_build.sources": "ee7415e6342b55aaac9574237b0e288a1ef2fa03",
    "zog.image_build.stages": "7895344e0503c735c8e8b8daaec2eee5a16994ac",
    "zog.image_build.temporary": "8935c337bb28c59e84682b3d5ef04e31d6eece09",
    "zog.image_build.test_fixtures": "44f1f518a7b0420cfd4fa6b6e435aaafb29ad383",
    "zog.image_build.toolchain_contract": "a6fd36400abb653e9830278dc0560671d384f137",
    "zog.image_build.toolchain_remote": "58f2ddaa9c6d999179da3f042b066e814bd4f804",
    "zog.image_build.trace_records": "befb5a85a9aefc30d41603d8726f6baef4dd3272",
    "zog.image_build.verification_observations": "91fe5270ea2521f06b5da4432e6da230dae126fc",
    "zog.image_build.worker_contracts": "6896e73cc43177c705bf47aaaeae6c512aca7be2",
    "zog.image_build.worker": "0425393deecb271e412da2d90f8fce158880a789",
}
IMAGE_BUILD_SOURCE_METADATA_BLOBS = {
    "LICENSE": "06ffa894fc527a7707aeffca336b7cdd73eaa45d",
    "LICENSES/BSD-3-Clause.txt": "7e1ffb223693647c1750e550d9fd7ee94ce4ee0b",
    "LICENSES/GPL-3.0-only.txt": "f6cdd22a6c1fbc887e08a215cb4beb3c47048041",
    "pyproject.toml": "2430b81d33e98a1ef9d924e4cc927a535f715eb6",
    "THIRD-PARTY-NOTICES.md": "6c097d650762127dd740f989e6da5b7de60dbeef",
    "zog-component.json": "ec28318cd8af441fc55af7e83a8b0ed7f2120c80",
}

_SIMPLE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")
_VOLATILE_ROOTS = (Path("/run"), Path("/tmp"), Path("/var/tmp"), Path("/dev"),
                   Path("/proc"), Path("/sys"))


def _numeric(value, label):
    require(type(value) is int and 0 < value < 2**31,
            "image-progress-profile", label)
    return str(value)


def _absolute(value, label):
    text = str(value)
    parsed = Path(text)
    require(
        _SIMPLE_PATH.fullmatch(text) is not None
        and str(parsed) == text
        and ".." not in parsed.parts
        and "." not in parsed.parts
        and parsed != Path("/"),
        "image-progress-profile",
        label,
    )
    return text


def _git_blob_sha(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _record_sha256(data):
    return base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).rstrip(b"=").decode()


def _protected_ancestry(path, stop, *, code="image-build-installed"):
    path = Path(path)
    stop = Path(stop)
    require(path.is_absolute() and stop.is_absolute(), code,
            "protected path must be absolute")
    try:
        path.relative_to(stop)
    except ValueError:
        require(False, code, "path is outside approved root")
    current = path
    while True:
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not (info.st_mode & 0o022),
                code, "installed software path is redirected or writable")
        if current == stop:
            break
        current = current.parent


def _producer_permissions(info, uid, gids):
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid == uid:
        return (mode >> 6) & 0o7
    if info.st_gid in gids:
        return (mode >> 3) & 0o7
    return mode & 0o7


def _protected_state_ancestry(state_root, producer_uid, producer_gids):
    current = Path("/")
    for part in Path(state_root).parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and not (info.st_mode & 0o022)
                and info.st_uid in (0, producer_uid),
                "image-build-identity",
                "image-build state ancestry is not protected")
        require(_producer_permissions(info, producer_uid, producer_gids) & 0o1,
                "image-build-identity",
                "image-build producer cannot traverse protected state ancestry")


def resolve_live_identities(image_build_state_root):
    """Resolve welcome and image-build identities from independent live host facts."""
    require(os.geteuid() == 0, "root-required",
            "live image observer identity resolution requires root")
    state_text = _absolute(
        image_build_state_root, "canonical image-build state root required"
    )
    state_root = Path(state_text)
    require(not any(state_root == root or root in state_root.parents
                    for root in _VOLATILE_ROOTS),
            "image-build-identity",
            "image-build state root must be durable")

    state_info = state_root.lstat()
    require(stat.S_ISDIR(state_info.st_mode) and not stat.S_ISLNK(state_info.st_mode)
            and not (state_info.st_mode & 0o022),
            "image-build-identity",
            "image-build state root is not protected")
    component = state_root / "image-build"
    component_info = component.lstat()
    require(stat.S_ISDIR(component_info.st_mode)
            and not stat.S_ISLNK(component_info.st_mode)
            and component_info.st_uid > 0 and component_info.st_gid > 0
            and not (component_info.st_mode & 0o022),
            "image-build-identity",
            "image-build component state has unsafe ownership or permissions")
    producer_uid = component_info.st_uid
    producer_gid = component_info.st_gid

    try:
        owner = pwd.getpwuid(producer_uid)
    except KeyError:
        require(False, "image-build-identity",
                "image-build state owner has no host account")
    require(owner.pw_uid == producer_uid and owner.pw_gid == producer_gid
            and len([row for row in pwd.getpwall()
                     if row.pw_uid == producer_uid]) == 1,
            "image-build-identity",
            "image-build host account disagrees with state ownership")
    producer_gids = set(os.getgrouplist(owner.pw_name, producer_gid))
    _protected_state_ancestry(state_root, producer_uid, producer_gids)
    require(_producer_permissions(state_info, producer_uid, producer_gids) & 0o5 == 0o5
            and _producer_permissions(component_info, producer_uid, producer_gids) & 0o5 == 0o5,
            "image-build-identity",
            "image-build producer cannot read/traverse its fixed state root")

    consumer_uid, consumer_gid = welcome_account()
    require(consumer_uid != producer_uid,
            "image-progress-profile",
            "host-welcome consumer and image-build producer must be distinct UIDs")
    return {
        "consumer_uid": consumer_uid,
        "consumer_gid": consumer_gid,
        "producer_uid": producer_uid,
        "producer_gid": producer_gid,
        "image_build_state_root": state_text,
        "evidence": {
            "welcome_account": "host-account-database",
            "image_build_state_owner": str(component),
            "image_build_account": owner.pw_name,
        },
    }


def verify_reviewed_source(source):
    """Verify the complete installable image-build Python tree and release metadata."""
    root = Path(source)
    require(root.is_dir() and not root.is_symlink(),
            "image-build-source", "reviewed image-build source root unavailable")
    package = root / "src/zog/image_build"
    actual = {
        path.relative_to(root).as_posix()
        for path in package.rglob("*.py")
        if path.is_file() and not path.is_symlink()
    }
    require(actual == set(IMAGE_BUILD_SOURCE_PYTHON_BLOBS),
            "image-build-source",
            "image-build Python source inventory differs from reviewed revision")
    observed = {}
    for relative, expected in IMAGE_BUILD_SOURCE_PYTHON_BLOBS.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "image-build-source",
                "reviewed image-build module missing or redirected")
        data = path.read_bytes()
        require(len(data) <= 2_000_000,
                "image-build-source",
                "reviewed image-build module exceeds size bound")
        blob = _git_blob_sha(data)
        require(blob == expected,
                "image-build-source",
                "image-build Python bytes differ from reviewed revision")
        observed[relative] = {"git_blob": blob, "sha256": _sha256(data)}
    for relative, expected in IMAGE_BUILD_SOURCE_METADATA_BLOBS.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "image-build-source",
                "reviewed image-build release metadata missing or redirected")
        data = path.read_bytes()
        require(_git_blob_sha(data) == expected,
                "image-build-source",
                "image-build release metadata differs from reviewed revision")
    return observed


def _wheel_record(distribution, root):
    text = distribution.read_text("RECORD")
    require(type(text) is str and 0 < len(text) <= 4_000_000,
            "image-build-installed",
            "aggregate wheel RECORD missing or excessive")
    rows = {}
    for row in csv.reader(io.StringIO(text)):
        require(len(row) == 3 and row[0] not in rows,
                "image-build-installed", "invalid aggregate wheel RECORD")
        rows[row[0]] = (row[1], row[2])
    record_files = [
        value for value in distribution.files or ()
        if str(value).endswith(".dist-info/RECORD")
    ]
    require(len(record_files) == 1,
            "image-build-installed", "aggregate RECORD path is ambiguous")
    record_path = Path(distribution.locate_file(record_files[0]))
    _protected_ancestry(record_path, root)
    info = record_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            "image-build-installed", "aggregate RECORD is not a protected file")
    return rows, _sha256(text.encode()), str(record_path)


def _loaded_image_build_modules():
    importlib.import_module("zog.image_build.post_install_progress_broker")
    importlib.import_module("zog.image_build.post_install_progress")
    result = {}
    for name, module in tuple(sys.modules.items()):
        if name == "zog.image_build" or name.startswith("zog.image_build."):
            origin = getattr(module, "__file__", None)
            if isinstance(origin, str) and origin.endswith(".py"):
                result[name] = module
    return result


def verify_installed(*, python_executable="/usr/bin/python3"):
    """Attest aggregate-loaded image-build observer modules to the reviewed Git tree."""
    require(os.geteuid() == 0, "root-required",
            "installed image-build observer attestation requires root")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "image-build-installed",
            "caller-selected Python import paths are not permitted")
    python_executable = _absolute(
        python_executable, "canonical approved Python executable required"
    )
    configured_python = Path(python_executable)
    require(configured_python.exists(),
            "image-build-installed", "approved Python executable is unavailable")
    running_python = Path(sys.executable).resolve()
    require(configured_python.resolve() == running_python,
            "image-build-installed",
            "attestation interpreter differs from approved service interpreter")
    _protected_ancestry(running_python, Path("/"))

    try:
        distribution = importlib.metadata.distribution("zog")
    except importlib.metadata.PackageNotFoundError:
        require(False, "image-build-installed",
                "aggregate zog distribution is not installed")
    require(distribution.metadata.get("Name") == "zog",
            "image-build-installed", "unexpected aggregate distribution name")
    root = Path(distribution.locate_file("")).resolve()
    _protected_ancestry(root, Path("/"))
    record, record_sha256, record_origin = _wheel_record(distribution, root)

    loaded = _loaded_image_build_modules()
    require("zog.image_build.post_install_progress_broker" in loaded
            and "zog.image_build.post_install_progress" in loaded,
            "image-build-installed",
            "reviewed image-build broker/projection did not load")
    observed = {}
    for module, value in sorted(loaded.items()):
        expected_blob = IMAGE_BUILD_MODULE_BLOBS.get(module)
        require(expected_blob is not None,
                "image-build-installed",
                "loaded image-build module is outside reviewed source inventory")
        origin = getattr(value, "__file__", None)
        require(type(origin) is str,
                "image-build-installed", "loaded image-build module has no origin")
        path = Path(origin)
        _protected_ancestry(path, root)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "image-build-installed",
                "loaded image-build module is not a protected regular file")
        data = path.read_bytes()
        require(len(data) <= 2_000_000,
                "image-build-installed", "installed image-build module exceeds size bound")
        git_blob = _git_blob_sha(data)
        require(git_blob == expected_blob,
                "image-build-installed",
                "installed image-build bytes differ from reviewed source")
        relative = path.resolve().relative_to(root).as_posix()
        require(relative in record,
                "image-build-installed",
                "loaded image-build module absent from aggregate RECORD")
        algorithm, separator, encoded = record[relative][0].partition("=")
        require(separator == "=" and algorithm == "sha256"
                and encoded == _record_sha256(data),
                "image-build-installed",
                "aggregate RECORD hash disagrees with loaded image-build module")
        observed[module] = {
            "origin": str(path.resolve()),
            "git_blob": git_blob,
            "sha256": _sha256(data),
            "record_path": relative,
        }

    return {
        "schema": "zog-host-welcome-image-progress-installed-attestation-v1",
        "status": "image-build-observer-installed-software-verified",
        "image_build_source_repository": IMAGE_BUILD_REPOSITORY,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
        "distribution": {
            "name": distribution.metadata["Name"],
            "version": distribution.version,
            "root": str(root),
            "record_origin": record_origin,
            "record_sha256": record_sha256,
        },
        "python_executable": str(running_python),
        "pythonpath_present": False,
        "modules": observed,
        "mutation_authorized": False,
        "production_activation_authorized": False,
    }


def _render(name, replacements):
    text = resource_files(__package__).joinpath("systemd", name).read_text()
    for key, value in replacements.items():
        text = text.replace("@" + key + "@", value)
    require("@" not in text, "image-progress-template",
            "unresolved unit template marker")
    return text.encode()


def stage(*, output, image_build_state_root, consumer_uid, producer_uid,
          producer_gid, image_build_source, python_executable="/usr/bin/python3",
          producer_source=None, identity_evidence=None):
    """Stage the dedicated image-build observer with already-verified numeric IDs."""
    require(os.geteuid() == 0, "root-required",
            "host-welcome image progress profile staging requires root")
    state_root = _absolute(
        image_build_state_root, "canonical image-build state root required"
    )
    python_executable = _absolute(
        python_executable, "canonical Python executable required"
    )
    welcome_uid = _numeric(
        consumer_uid, "authoritative host-welcome consumer UID required"
    )
    image_uid = _numeric(producer_uid, "image-build producer UID required")
    image_gid = _numeric(producer_gid, "image-build producer GID required")
    require(consumer_uid != producer_uid, "image-progress-profile",
            "host-welcome consumer and image-build producer must be distinct UIDs")
    source_blobs = verify_reviewed_source(image_build_source)

    replacements = {
        "WELCOME_UID": welcome_uid,
        "IMAGE_BUILD_UID": image_uid,
        "IMAGE_BUILD_GID": image_gid,
        "IMAGE_BUILD_STATE_ROOT": state_root,
        "PYTHON_EXECUTABLE": python_executable,
    }
    rendered = {
        UNIT_SOCKET: _render(UNIT_SOCKET + ".in", replacements),
        UNIT_SERVICE: _render(UNIT_SERVICE + ".in", replacements),
    }
    if producer_source is not None:
        packaged = resource_files(__package__).joinpath("systemd")
        for template in (UNIT_SOCKET + ".in", UNIT_SERVICE + ".in"):
            require(
                (Path(producer_source) / "examples/systemd" / template).read_bytes()
                == packaged.joinpath(template).read_bytes(),
                "image-progress-template",
                "packaged/reference template mismatch",
            )

    policy = {
        "schema": POLICY_SCHEMA,
        "enabled": True,
        "consumer_uid": consumer_uid,
        "producer_uid": producer_uid,
        "socket": SOCKET_PATH,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
    }
    manifest = {
        "schema": 1,
        "kind": PROFILE_KIND,
        "runtime_model": "host-rootfs-bootstrap-consumer",
        "consumer_uid": consumer_uid,
        "producer_uid": producer_uid,
        "producer_gid": producer_gid,
        "image_build_state_root": state_root,
        "identity_evidence": identity_evidence,
        "socket": SOCKET_PATH,
        "policy": POLICY_PATH,
        "python_executable": python_executable,
        "image_build_source_repository": IMAGE_BUILD_REPOSITORY,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
        "host_welcome_consumer_commit": HOST_WELCOME_CONSUMER_COMMIT,
        "application_allowlist": list(GRAPHICAL_APPLICATIONS),
        "image_build_python_source_inventory": source_blobs,
        "selection_binding": {
            "owner": "host-install",
            "receipt_and_sequence_required": True,
            "selected_rootfs_generation_required_for_compatible_view": True,
            "absence_or_mismatch": "unknown",
        },
        "boot_recovery_policy": {
            "snapshot_must_name_current_boot": True,
            "retained_terminal_command_may_name_older_controller_boot": True,
            "selection_and_publication_may_survive_reboot": True,
            "observer_may_not_resume_or_retry_work": True,
        },
        "visibility": {
            "host_welcome_socket": SOCKET_PATH,
            "host_welcome_policy": POLICY_PATH,
            "station_progress_socket_inherited": False,
            "controller_progress_socket_inherited": False,
            "raw_image_build_state_inherited": False,
            "image_build_credentials_inherited": False,
            "arbitrary_host_run_binding": False,
        },
        "units": {
            UNIT_SOCKET: "enable-after-installed-software-attestation-and-native-acceptance",
            UNIT_SERVICE: "socket-activated",
        },
        "boot_dependencies": {
            "state": False,
            "station_access": False,
            "box_control_for_getty": False,
            "network": False,
            "image_build": False,
            "graphics": False,
            "getty_requires_observer": False,
        },
        "mutation_authority": {
            "submit": False,
            "resume": False,
            "cancel": False,
            "publish": False,
            "install": False,
            "service_start": False,
            "state_write": False,
            "reboot": False,
        },
        "services_enabled": False,
        "installed_software_verified": False,
        "native_acceptance_complete": False,
    }

    output = Path(output).absolute()
    parent = directory(str(output.parent))
    root = None
    try:
        root = ensure_directory(parent, output.name, 0, 0, 0o700)
        with lock(root):
            allowed = {
                ".host-install.lock", "profile.json", ".pending.profile.json",
                "etc", ".pending-dir.etc",
            }
            require(set(os.listdir(root)) <= allowed,
                    "profile-conflict",
                    "unexpected image observer overlay contents")
            publish(root, "profile.json", canonical(manifest), 0o444)

            etc = systemd = system = zog = None
            try:
                etc = ensure_directory(root, "etc", 0, 0, 0o755)
                systemd = ensure_directory(etc, "systemd", 0, 0, 0o755)
                system = ensure_directory(systemd, "system", 0, 0, 0o755)
                for name, data in rendered.items():
                    publish(system, name, data, 0o444)
                zog = ensure_directory(etc, "zog", 0, 0, 0o755)
                publish(
                    zog,
                    "host-welcome-image-progress-observer.json",
                    canonical(policy),
                    0o444,
                )
            finally:
                for fd in (zog, system, systemd, etc):
                    if fd is not None:
                        os.close(fd)
        return {
            "status": "host-welcome-image-progress-profile-staged",
            "output": str(output),
            "consumer_uid": consumer_uid,
            "producer_uid": producer_uid,
            "socket": SOCKET_PATH,
            "policy": POLICY_PATH,
            "services_enabled": False,
            "installed_software_verified": False,
            "state_modified": False,
        }
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


def stage_live(*, output, image_build_state_root, image_build_source,
               python_executable="/usr/bin/python3", producer_source=None):
    """Resolve independent live UIDs and stage the exact reviewed image observer."""
    identities = resolve_live_identities(image_build_state_root)
    return stage(
        output=output,
        image_build_state_root=identities["image_build_state_root"],
        consumer_uid=identities["consumer_uid"],
        producer_uid=identities["producer_uid"],
        producer_gid=identities["producer_gid"],
        image_build_source=image_build_source,
        python_executable=python_executable,
        producer_source=producer_source,
        identity_evidence=identities["evidence"],
    )
