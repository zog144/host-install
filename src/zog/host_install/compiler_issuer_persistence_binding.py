"""Read-only approval binding for a replacement compiler unit with issuer persistence.

The existing issuer storage / mount guard remains independent. This module
proves which *replacement* unit hash was approved without treating the original
rollback digest as the replacement digest, or changing an approval/receipt.
The issuer persistence guard owner must independently consume/review the
contract; this module does not silently modify systemd or authorize starts.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex

SCHEMA = "zog-compiler-issuer-replacement-unit-binding-v1"
ISSUER_DROPIN = "issuer-persistence.conf"
COMPILER_UNIT = "zog-certbot-seed-root.service"
RETIRED_COMPILER_RUNTIME = "/opt/zog/fonts-controller-d9dfd6c0-20261114"
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
                value = line.partition("=")[2].strip()
                _need(value and not value.startswith("-"),
                      "issuer prestart guard must not ignore failures")
                try:
                    argv = shlex.split(value)
                except ValueError as error:
                    raise IssuerBindingHold("invalid issuer prestart argv") from error
                _need(argv and argv[0].startswith("/"),
                      "issuer prestart guard executable is invalid")
                pres.append(argv)
            elif line.startswith("ReadOnlyPaths="):
                value = line.partition("=")[2].split()
                _need(value and all(path.startswith("/") and
                      ".." not in path.split("/") for path in value),
                      "issuer read-only storage paths are invalid")
                readonly.extend(value)
    _need(pres and readonly, "issuer prestart and read-only mount checks required")
    return pres, readonly


def _retiring_compiler(selection):
    rollback = selection["rollback"]
    path = rollback.get("original_runtime")
    # Exact reviewed compiler tree, never the issuer application tree.
    _need(type(path) is str and path == RETIRED_COMPILER_RUNTIME,
          "original runtime is not the reviewed retiring compiler")
    return path


def _within_compiler(token, root):
    # Only immutable canonical absolute tokens identify a retiring path.
    # Raw prefix alone admits /old/compiler/../issuer and would waive issuer
    # protections. posixpath is lexical: never resolve Host symlinks here.
    return (type(token) is str and token.startswith("/")
            and "//" not in token and token == posixpath.normpath(token)
            and (token == root or token.startswith(root + "/")))


def _effective_prestarts(effective):
    commands = effective.get("ExecStartPre")
    _need(type(commands) is list and bool(commands),
          "issuer effective prestart checks missing")
    validated = []
    for item in commands:
        _need(type(item) is dict and set(item) == {"path", "argv", "flags"},
              "unreviewed issuer effective prestart identity")
        flags = item["flags"]
        _need(type(flags) is dict and set(flags) ==
              {"ignore_errors", "flags"},
              "invalid issuer effective execution flags")
        try:
            argv = shlex.split(item["argv"])
        except (TypeError, ValueError) as error:
            raise IssuerBindingHold("invalid issuer effective prestart argv") from error
        _need(type(item["path"]) is str and argv and
              argv[0] == item["path"] and item["path"].startswith("/"),
              "invalid issuer effective executable")
        validated.append((item, argv))
    return validated


def _issuer_and_retirement_checks(selection, pres, mounts,
                                  original_effective, selected_effective):
    old_root = _retiring_compiler(selection)
    old = _effective_prestarts(original_effective)
    new = _effective_prestarts(selected_effective)
    issuer_flags = {"ignore_errors": "no", "flags": ""}
    for argv in pres:
        for commands in (old, new):
            _need(any(args == argv and item["flags"] == issuer_flags
                      for item, args in commands),
                  "issuer persistence prestart or flags removed")
    selected_ids = [item for item, _ in new]
    for item, argv in old:
        retired = (_within_compiler(item["path"], old_root)
                   or any(_within_compiler(arg, old_root) for arg in argv))
        _need(retired or item in selected_ids,
              "nonretired prestart removed from issuer service")
    original_paths = original_effective.get("ReadOnlyPaths")
    selected_paths = selected_effective.get("ReadOnlyPaths")
    _need(type(original_paths) is str and type(selected_paths) is str,
          "issuer read-only mount properties missing")
    old_paths = set(original_paths.split())
    selected_set = set(selected_paths.split())
    _need(set(mounts) <= old_paths and set(mounts) <= selected_set,
          "issuer persistence read-only mount removed")
    _need(all(_within_compiler(path, old_root) or path in selected_set
              for path in old_paths),
          "nonretired or issuer read-only mount removed")
    for key in ("Requires", "After"):
        prior = original_effective.get(key)
        chosen = selected_effective.get(key)
        _need(type(prior) is str and type(chosen) is str and
              set(prior.split()) <= set(chosen.split()),
              "issuer backing mount dependency changed: " + key)


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
    _issuer_and_retirement_checks(
        selection, prestart, mounts, original_effective, selected_effective)
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



def verify_selected_replacement_digest(selection, approved_sha256,
                                       approved_selection_bytes, receipt,
                                       transaction, active_unit_bytes,
                                       preserved_issuer_dropin,
                                       selected_issuer_dropin,
                                       live_issuer_dropin, live_issuer_metadata):
    """Strict selected-only replacement digest predicate for the future guard.

    This function is NOT the installed ExecStartPre helper. It is a narrow
    digest authorization *input* to that helper, and must be invoked only
    alongside its independently attested issuer storage/mount/grant checks.
    """
    # Bind the parsed, independently reviewed manifest to its *actual bytes*.
    # An arbitrary caller-supplied dictionary or asserted selection SHA is
    # insufficient even if it superficially matches transaction fields.
    _digest(approved_sha256)
    _need(type(approved_selection_bytes) is bytes and
          hashlib.sha256(approved_selection_bytes).hexdigest() == approved_sha256,
          "approved selection bytes differ from pinned SHA256")
    def unique_pairs(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise IssuerBindingHold("duplicate key in approved selection")
            seen[key] = value
        return seen
    try:
        observed_selection = json.loads(
            approved_selection_bytes.decode("utf-8"),
            object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError) as error:
        raise IssuerBindingHold("approved selection JSON invalid") from error
    _need(type(observed_selection) is dict and
          observed_selection == selection,
          "parsed approved selection differs from authenticated bytes")
    binding = reviewed_replacement_binding(
        selection, approved_sha256, receipt, preserved_issuer_dropin,
        selected_issuer_dropin)
    # The preserved and staged copies are not evidence of what systemd will
    # execute. Require the *live* drop-in's bytes and disk metadata to match
    # the exact approved selected composition before admitting a new unit SHA.
    selected_issuer = _member(selection["composition"]["selected_dropins"])
    _need(type(live_issuer_dropin) is bytes and
          type(live_issuer_metadata) is dict,
          "live issuer persistence drop-in missing or invalid")
    _need(live_issuer_dropin == selected_issuer_dropin and
          hashlib.sha256(live_issuer_dropin).hexdigest() ==
              selected_issuer["sha256"],
          "live issuer persistence drop-in bytes differ from approval")
    _need(live_issuer_metadata == {
              "name": ISSUER_DROPIN,
              "sha256": selected_issuer["sha256"],
              "size": selected_issuer["size"],
              "mode": selected_issuer["mode"],
              "uid": selected_issuer["uid"],
              "gid": selected_issuer["gid"],
          } and len(live_issuer_dropin) == selected_issuer["size"],
          "live issuer persistence drop-in metadata differs from approval")
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
        "live_issuer_dropin_verified": True,
        "issuer_native_storage_rechecked": False,
        "startup_authorized": False,
    }
