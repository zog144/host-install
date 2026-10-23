"""Pure non-resident installation-plan projection.

This module never mounts, formats, partitions, enables units or creates identities.
It turns a validated schema-2 non-resident STATE bundle into the exact root-owned
configuration contract that a later privileged installer must apply and verify.
"""
from .state_contract import canonical, digest, installation_mode, require, validate

PLAN_SCHEMA = 1
PLAN_KIND = 'zog-non-resident-installation-plan'


def build_plan(bundle):
    validate(bundle)
    installation = bundle['installation']
    require(installation_mode(installation) == 'non-resident',
            'installation-mode', 'non-resident installation record required')
    bootstrap = bundle['bootstrap']
    state = bootstrap['state']
    recorded = installation['installer_recorded']

    files = []
    for name in ('accounts', 'installation', 'bootstrap'):
        value = bundle[name]
        files.append({
            'path': f'/etc/zog/host-install/{name}.json',
            'uid': 0,
            'gid': 0,
            'mode': '0444',
            'sha256': digest(value),
        })

    return {
        'schema': PLAN_SCHEMA,
        'kind': PLAN_KIND,
        'installation_id': installation['installation_id'],
        'installation_record_sha256': digest(installation),
        'installation_mode': 'non-resident',
        'host_os': recorded['host_os'],
        'state': {
            'mount_point': '/state',
            'filesystem_type': 'ext4',
            'state_volume_id': state['state_volume_id'],
            'partition_partuuid': state['partition_partuuid'],
            'filesystem_uuid': state['filesystem_uuid'],
            'device_reference': f"/dev/disk/by-partuuid/{state['partition_partuuid']}",
            'root_device_exclusion_required': True,
            'writable_mount_required': True,
            'nested_mounts_forbidden': True,
        },
        'configuration_files': files,
        'systemd': {
            'mount_unit': {
                'name': 'state.mount',
                'what': f"/dev/disk/by-partuuid/{state['partition_partuuid']}",
                'where': '/state',
                'type': 'ext4',
                'options': ['rw', 'nodev', 'nosuid'],
                'uid': 0,
                'gid': 0,
                'mode': '0644',
                'host_os_boot_required': False,
            },
            'zog_service_ordering': {
                'requires': ['state.mount'],
                'after': ['state.mount'],
                'binds_to': ['state.mount'],
                'state_failure_blocks_zog_only': True,
            },
        },
        'state_initialization': {
            'mounting_authorizes_identity': False,
            'authorization_id': bootstrap['initialization']['authorization_id'],
            'policy': bootstrap['initialization']['policy'],
            'preparation_required_before_identity': True,
        },
        'removal': {
            'disable_zog_services_first': True,
            'remove_service_integration': True,
            'retain_state_default': True,
            'state_destruction_requires_separate_explicit_operation': True,
        },
        'execution': {
            'plan_only': True,
            'device_writes_authorized': False,
            'formatting_authorized': False,
            'identity_initialization_authorized': False,
            'host_os_management_must_remain_available': True,
        },
    }


def validate_plan(plan):
    require(type(plan) is dict and set(plan) == {
                'schema', 'kind', 'installation_id', 'installation_record_sha256',
                'installation_mode', 'host_os', 'state', 'configuration_files',
                'systemd', 'state_initialization', 'removal', 'execution',
            }, 'record-fields', 'unexpected non-resident plan fields')
    require(type(plan['schema']) is int and type(plan['schema']) is not bool and
            plan['schema'] == PLAN_SCHEMA and plan['kind'] == PLAN_KIND,
            'unsupported-schema', PLAN_KIND)
    require(plan['installation_mode'] == 'non-resident',
            'installation-mode', 'non-resident required')
    require(plan['host_os'] == {
                'management': 'externally-managed',
                'boot': 'externally-managed',
                'root_filesystem': 'externally-managed',
            }, 'host-os-management', 'external host ownership required')
    execution = plan['execution']
    require(execution == {
                'plan_only': True,
                'device_writes_authorized': False,
                'formatting_authorized': False,
                'identity_initialization_authorized': False,
                'host_os_management_must_remain_available': True,
            }, 'plan-authority', 'plan must not grant execution authority')
    require(plan['removal'].get('retain_state_default') is True and
            plan['removal'].get('state_destruction_requires_separate_explicit_operation') is True,
            'removal-policy', 'STATE retention must be the default')
    require(plan['systemd'].get('zog_service_ordering', {}).get('state_failure_blocks_zog_only') is True,
            'systemd-ordering', 'STATE failure must block Zog without owning host OS boot')
    return plan
