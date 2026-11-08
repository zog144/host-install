"""Immutable opt-in consumer source selection for retained registry identity.

The two companion PRs are source candidates, NOT installed production pins.
Neither a caller assertion nor a signed registrar mapping authorizes mutation.
"""
from .state_contract import StateError, require

HOST_IDENTIFY_REVISION = "39972469ec01017f83dea488ca5b868d9d691062"
HOST_DISCOVER_REVISION = "99965cf6d66f68c92affbedf585bf7b366f4d095"
HOST_INSTALL_BASE = "dfce38a239957b98c1d433dac94ea9fc4b0918fd"
COMPLETION_SCHEMA = "zog-retained-legacy-state-identity-completion-v1"
CONSUMER_SCHEMA = "zog-retained-legacy-state-consumer-source-selection-v1"
CONSUMER_INTERFACE = "zog.host_identify.retained_legacy.load_retained_legacy_fd"
DAEMON_MODE = "existing-legacy-migration"
IDENTITY_DIRECTORY = "/state/host-discover/identity"
CONSUMER_SELECTION = {
    "schema": CONSUMER_SCHEMA,
    "host_identify_revision": HOST_IDENTIFY_REVISION,
    "host_discover_revision": HOST_DISCOVER_REVISION,
    "host_install_base": HOST_INSTALL_BASE,
    "completion_schema": COMPLETION_SCHEMA,
    "identity_loader": CONSUMER_INTERFACE,
    "daemon_mode": DAEMON_MODE,
    "identity_directory": IDENTITY_DIRECTORY,
}


def verify_consumer_selection(value):
    """Allow exactly the reviewed disabled consumer, not a boolean or caller pin."""
    require(type(value) is dict and value == CONSUMER_SELECTION,
            "migration-consumer", "unreviewed retained identity consumer")
    return dict(CONSUMER_SELECTION)
