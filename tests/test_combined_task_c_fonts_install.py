"""Source and installed-package test: one host-install supports both operations."""
import importlib.metadata as metadata
import inspect
from pathlib import Path

from zog.host_install import task_c_local_install as task_c
from zog.host_install import fonts_project_migration as fonts


def test_one_checkout_contains_both_capabilities():
    assert callable(task_c.stage) and callable(task_c.source_plan)
    assert callable(fonts.operation) and callable(fonts.main)
    assert task_c.SCHEMA
    assert fonts.NEW == "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
    assert Path(inspect.getfile(task_c)).parents[0] == Path(inspect.getfile(fonts)).parents[0]
    assert task_c.os.geteuid is fonts.os.geteuid


def test_distribution_installs_both_commands_from_one_wheel():
    ep={item.name: item.value
        for item in metadata.distribution("host-install").entry_points
        if item.group == "console_scripts"}
    assert ep["host-install-task-c"] == "zog.host_install.task_c_local_install:main"
    assert ep["host-install-fonts-project-migrate"] == "zog.host_install.fonts_project_migration:main"
