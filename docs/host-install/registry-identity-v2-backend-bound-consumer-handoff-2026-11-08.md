# 2026-11-08 — registry identity v2 backend-bound consumer handoff

Origin: [know-file handoff](https://github.com/zog144/know-file/blob/2fc3395eac067b8f31c89eff8bb93a777d8502cf/host-install/handoffs/registry-identity-directory-state-consumer-2026-11-08.md). Source only; selected registry Host remains **native HOLD**.

## Implemented in host-install draft PR #35

`src/zog/host_install/graphical_registry_identity_mapping_v2.py` adds `prepare_unsigned` and `verify_signed`. It preserves `graphical_registry_identity_mapping.py`'s original v1 mounted-volume contract, using distinct `zog-registry-native-identity-mapping-v2` schema/domain. Only a separately pinned registrar public key can verify the domain-separated Ed25519 mapping; there is no signing/key allocation API. The independently signed root-control v3 registry installation scope is also verified with the distinct pinned registry public key.

The closed signed record binds exact legacy host-discover UUID and host-identify fingerprint, legacy installation/STATE UUIDs, real signed opaque Host/installation/STATE and registry/controller IDs, selected AWS instance and region, registrar/registry public key pins, and digest of the signed registry record. A supplied `observation` must be from a trusted native reader, never gateway JSON.

**Mounted-volume:** distinct v2 record mode `mounted-volume` requires mountpoint `/state`, mounted=true, volume ID, filesystem UUID/PARTUUID, mount ID, device and STATE marker digest. Existing version-1 records remain version-1 with no transparent conversion.

**Root-directory:** mode `root-directory` requires mountpoint `/state`, mounted=false, root mount ID/major-minor device, STATE directory device equal to root device, positive inode, uid/gid 0, mode 0755, root filesystem UUID/PARTUUID and canonical state marker digest. It explicitly cannot supply the independent Task C ledger/anchor mounts. The native loader must additionally recheck source topology, retained directory descriptor, actual XFS/ext4 root, symlink/nested mount exclusion, marker byte equality, and no path replacement, as in PR35's `state_inspect`. A copied static `observation` does not prove these facts.

**Negative regressions:** signed v1 domain under v2; switched/mixed backend; missing/changed marker; changed UUID, Host, fingerprint, EBS/root device, mount, directory inode or registry; copied instance; missing/extra fields and wrong registrar signature. Every result has `native_accepted=False`, `broker_admission=False`, `ssm_authorized=False`.

## Exact native evidence required from Work

1. Authenticate selected registry Host AWS IID/account/region, previously enrolled host-discover UUID and Ed25519 public-key fingerprint, installation ID, separately signed registry H64/registry scope and pinned registrar key. Existing native report found **no installed /state**, no installed host-install configuration and XFS root.
2. Reconcile Work's unpublished root-directory marker bytes against PR35's canonical schema (and original directory preparation contract). Do not provision an existing populated directory without explicit approval.
3. Produce fresh selected-Host read-only observation from `/proc/self/mountinfo`, kernel block topology, real XFS root UUID/PARTUUID, retained /state directory descriptor (dev, inode, uid, gid, mode), canonical marker bytes, matching `bootstrap.json` and `installation.json` digest and independently verified provenance. Reject missing /state, symlinks, nested mounts, changed inode, cross-Host STATE.
4. Only the enrolled registrar may issue the v2 signature after fresh authenticated readback. The registrar private key stays out of host-install runtime and host-deploy gateway. Keep original signed registry scope and source immutable.
5. **Still unimplemented:** a protected, per-invocation/native-observation adapter that conveys the authenticated v2 result from host-install to root-control v3 owner/broker and host-deploy, including selected wheel RECORD/units/service socket/credential and source revisions. Do not consume a caller-provided `native_accepted` boolean as admission.
6. Complete root-control PR47 / host-deploy PR30 / host-install PR34 or PR35 exact-three-owner source integration and tests, then Work performs native acceptance of genuine STATE and two **separate** protected Task C mounts, external rollback-independent anchor, GetObject-only broker credentials and SSM send fence. Keep all native admission flags disabled until separately authorized.

## Source verification

[Registry-storage exact-head CI run #42484706431](https://github.com/zog144/host-install/actions/runs/42484706431) passed 153 tests each on Python 3.12 and 3.13. This has **not** installed anything on the registry Host or authenticated any true native mapping.

The new mapping is intentionally an explicit v2 candidate, **not** a drop-in reinterpretation or automatic migration of the earlier v1 record and not a certified native consumer.
