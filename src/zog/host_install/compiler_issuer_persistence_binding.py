"""Read-only approval binding for a replacement compiler unit with issuer persistence.

The existing issuer storage / mount guard remains independent. This module
proves which *replacement* unit hash was approved without treating the original
rollback digest as the replacement digest, or changing an approval/receipt.
The issuer persistence guard owner must independently consume/review the
contract; this module does not silently modify systemd or authorize starts.
"""
from __future__ import annotations

import hashlib
import re

SCHEMA = "zog-compiler-issuer-replacement-unit-binding-v1"
ISSUER_DROPIN = "issuer-persistence.conf"
COMPILER_UNIT = "zog-certbot-seed-root.service"
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class IssuerBindingHold(RuntimeError):
    pass


def _need(value, message):
    if not value:
        raise IssuerBindingHold(message)


def _digest(value):
    _need(type(value) is str and _SHA.fullmatch(value) is not None,
          "invalid unit or selection digest")
    return value


def _member(entries):
    _need(type(entries) is list, "missing reviewed issuer drop-in inventory")
    matches = [entry for entry in entries
               if type(entry) is dict and entry.get("name") == ISSUER_DROPIN]
    _need(len(matches) == 1, "issuer-persistence drop-in missing or duplicated")
    entry = matches[0]
    _digest(entry.get("sha256"))
    _need(entry.get("uid") == 0 and entry.get("gid") == 0 and
          entry.get("mode") in (0o600, 0o640, 0o644),
          "issuer-persistence ownership or permissions changed")
    return entry


def _guards_from_dropin(body):
    _need(type(body) is bytes and len(body) > 0,
          "missing issuer-persistence guard bytes")
    try:
        lines = body.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise IssuerBindingHold("invalid issuer-persistence encoding") from error
    section = ""
    pres = []
    readonly = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Service]":
            if line.startswith("ExecStartPre="):
                _need(line.partition("=")[2].strip(),
                      "issuer prestart guard was cleared")
                pres.append(line.partition("=")[2].strip())
            elif line.startswith("ReadOnlyPaths="):
                _need(line.partition("=")[2].strip(),
                      "issuer read-only storage mount was cleared")
                readonly.extend(line.partition("=")[2].split())
    _need(pres and readonly, "issuer prestart and read-only mount checks required")
    return pres, readonly


def reviewed_replacement_binding(selection, approved_sha256, receipt,
                                 preserved_issuer_dropin, selected_issuer_dropin):
    """Bind replacement to approved selection while retaining issuer baseline.

    Call after the independent selection verifier and protected custody checks.
    No writes; the issuer guard owner must still verify storage identity,
    mounted backing device, filesystem permissions and startup preconditions.
    """
    _digest(approved_sha256)
    _need(type(selection) is dict and type(receipt) is dict,
          "missing approved selection or protected issuer baseline")
    service = selection.get("service")
    comp = selection.get("composition")
    rollback = selection.get("rollback")
    _need(type(service) is dict and service.get("name") == COMPILER_UNIT and
          type(comp) is dict and type(rollback) is dict,
          "issuer replacement binding requires reviewed compiler selection")
    _need(receipt.get("service") == COMPILER_UNIT and
          receipt.get("release_id") == selection.get("release_id"),
          "issuer rollback baseline belongs to another release")
    original = _digest(rollback.get("unit_sha256"))
    replacement = _digest(service.get("staged_sha256"))
    _need(original != replacement, "not a replacement compiler unit")
    _need(type(comp.get("original_fragment")) is dict and
          type(comp.get("selected_fragment")) is dict and
          comp["original_fragment"].get("sha256") == original and
          comp["selected_fragment"].get("sha256") == replacement and
          comp["selected_fragment"].get("path") == service.get("staged_unit") and
          receipt.get("unit_sha256") == original and
          type(receipt.get("original_fragment")) is dict and
          receipt["original_fragment"].get("sha256") == original,
          "replacement not bound to selected digest or original baseline")
    _need(receipt.get("original_fragment") == comp["original_fragment"] and
          receipt.get("original_dropins") == comp.get("original_dropins"),
          "issuer original rollback composition differs")
    original_issuer = _member(comp["original_dropins"])
    selected_issuer = _member(comp.get("selected_dropins"))
    _need(original_issuer == selected_issuer,
          "issuer storage/mount guard drop-in was changed")
    _need(type(preserved_issuer_dropin) is bytes and
          type(selected_issuer_dropin) is bytes,
          "issuer persistence drop-in must be exact bytes")
    _need(hashlib.sha256(preserved_issuer_dropin).hexdigest() ==
          original_issuer["sha256"] and
          preserved_issuer_dropin == selected_issuer_dropin,
          "issuer guard bytes differ from protected rollback and successor")
    prestart, mounts = _guards_from_dropin(preserved_issuer_dropin)
    original_effective = comp.get("original_effective")
    selected_effective = comp.get("selected_effective")
    _need(type(original_effective) is dict and
          type(selected_effective) is dict,
          "missing approved issuer effective restrictions")
    _need(original_effective.get("ExecStartPre") ==
          selected_effective.get("ExecStartPre") and
          type(selected_effective.get("ExecStartPre")) is list and
          len(selected_effective["ExecStartPre"]) >= len(prestart),
          "issuer persistence prestart checks changed")
    original_paths = original_effective.get("ReadOnlyPaths")
    selected_paths = selected_effective.get("ReadOnlyPaths")
    _need(type(original_paths) is str and type(selected_paths) is str and
          set(mounts) <= set(original_paths.split()) and
          set(mounts) <= set(selected_paths.split()),
          "issuer persistent storage read-only mounts changed")
    for key in ("Requires", "After"):
        prior = original_effective.get(key)
        chosen = selected_effective.get(key)
        _need(type(prior) is str and type(chosen) is str and
              set(prior.split()) <= set(chosen.split()),
              "issuer backing mount dependency changed: " + key)
    return {
        "schema": SCHEMA,
        "service": COMPILER_UNIT,
        "release_id": selection["release_id"],
        "approved_selection_sha256": approved_sha256,
        "original_rollback_unit_sha256": original,
        "approved_replacement_unit_sha256": replacement,
        "issuer_persistence_dropin_sha256": original_issuer["sha256"],
        "issuer_persistence_dropin_name": ISSUER_DROPIN,
        "issuer_prestart_checks_preserved": True,
        "issuer_readonly_mounts_preserved": True,
        "issuer_dependency_checks_preserved": True,
        "issuer_native_storage_rechecked": False,
        "startup_authorized": False,
    }



def verify_selected_replacement_digest(selection, approved_sha256, receipt,
                                       transaction, active_unit_bytes,
                                       preserved_issuer_dropin,
                                       selected_issuer_dropin):
    """Strict selected-only replacement digest predicate for the future guard.

    This function is NOT the installed ExecStartPre helper. It is a narrow
    digest authorization *input* to that helper, and must be invoked only
    alongside its independently attested issuer storage/mount/grant checks.
    """
    binding = reviewed_replacement_binding(
        selection, approved_sha256, receipt, preserved_issuer_dropin,
        selected_issuer_dropin)
    _need(type(transaction) is dict,
          "missing protected issuer selection transaction")
    _need(transaction.get("state") == "selected",
          "replacement digest requires durable selected transaction")
    _need(transaction.get("schema") == "zog-compiler-controller-versioned-installer-v1",
          "replacement transaction schema differs")
    _need(transaction.get("release_id") == binding["release_id"] and
          transaction.get("service") == binding["service"] and
          transaction.get("selection_sha256") == approved_sha256,
          "replacement transaction is not bound to approved selection")
    _need(transaction.get("issuer_replacement_binding") == binding and
          transaction.get("old_unit_sha256") ==
              binding["original_rollback_unit_sha256"] and
          transaction.get("new_unit_sha256") ==
              binding["approved_replacement_unit_sha256"],
          "protected transaction replacement binding or rollback differs")
    comp = selection["composition"]
    _need(transaction.get("old_dropins") == comp["original_dropins"] and
          transaction.get("new_dropins") == comp["selected_dropins"],
          "replacement transaction drop-in set differs from approval")
    _need(type(active_unit_bytes) is bytes and
          hashlib.sha256(active_unit_bytes).hexdigest() ==
              binding["approved_replacement_unit_sha256"],
          "active compiler unit is not the approved replacement")
    return {
        "schema": "zog-compiler-issuer-selected-digest-evidence-v1",
        "selection_sha256": approved_sha256,
        "approved_replacement_unit_sha256":
            binding["approved_replacement_unit_sha256"],
        "original_rollback_unit_sha256":
            binding["original_rollback_unit_sha256"],
        "selected_transaction_verified": True,
        "issuer_native_storage_rechecked": False,
        "startup_authorized": False,
    }
