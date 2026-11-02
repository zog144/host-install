# Protected graphical current-signing-authority installation — source candidate

**Owners:** host-install + root-control Regular · [host-install #14](https://github.com/zog144/host-install/issues/14) · consumer [host-deploy PR #11](https://github.com/zog144/host-deploy/pull/11).

## Protected trust and entrypoint

`graphical_protected_authority_install.install_current_authority(approved_pin_bytes, approval_bytes)`
is the only proposed protected installer owner entrypoint. It does not accept an arbitrary
directory descriptor, operator public key, pinned original identity signer, checkpoint
key, network endpoint or authority callback from the invoking request. It opens
the *existing* fixed public `/etc/zog/host-deploy` 0755 and separate root-private
`/etc/zog/host-install/graphical-current-authority` 0700 through root-owned
O_NOFOLLOW ancestry. The module does **not** create a directory, canonical
STATE, private Host signing key, issuer key, or a live service.

Root-private 0600 trust inputs must be installed by a **separately approved
native bootstrap** before the first authorized current-key installation:
- `original-graphical-installation-identity-pin-v1.json` — original independent
  Ed25519 installation-identity signer, distinct from operator, external issuer,
  and selected graphical Host key.
- `original-graphical-operator-pin-v1.json` — independently approved operator
  Ed25519 rotation signer, with pinned public-key SHA-256.
- `original-graphical-authority-grant-v1.json` — canonical independently
  signed original Host, installation, **STATE volume**, graphical policy,
  immutable source revision, wheel RECORD digest, operator-key identity,
  external monotonic issuer identity and minimum authorization revision.
- `original-graphical-installed-source-v1.json` — protected identity and
  source/RECORD attestation bound to the exact original grant digest.

The source contract checks strict schemas, ownership/permissions, signatures,
original identity and signed authorized rotation before any mutation. The source
record is a *protected evidence contract*, **not independent proof of actual
installed wheel bytes**; native Work must establish and verify its source/RECORD
attestation and original installation provenance.

## Irreversible rotation / recovery

The protected source reuses the existing fixed local `graphical-current-authority.lock`
and `graphical_rotation_checkpoint.rotate_checked_source`. A new signed
operator epoch is checked against a fresh independently authenticated external
checkpoint. A root-only no-replacement per-epoch key-use claim is written under
the local rotation lock **after** the public pending-denial marker but **before**
external compare-and-advance. Previously used signing public keys cannot be
introduced at any later epoch, even after multiple rotations. Each key-use
claim also binds the exact operator authorization revision. Subsequent epochs
cannot lower that revision, and a same-byte retry must match the complete
original Host/installation/grant/key/approval/revision claim, rather than
just its pin and approval hashes. This only proves monotonicity relative to
retained protected claims: a separately installed current-authorization
checkpoint remains necessary to recognize an approval revoked outside this
Host. The source
preflight also refuses a known retired key before creating a pending marker;
the check is repeated under the writer lock.

External compare-and-advance happens before private epoch/public-pin replacement,
followed by fresh signed checkpoint verification. The pending marker is only
removed after exact private and public readback. If interrupted, the same signed
approval/epoch/key may recover; another signed key, old epoch or changed original
grant cannot substitute. A lost response or external outage remains fail closed.
If the original epoch history predates these claims, the protected installer
**denies** until independently authorized migration/reconstruction is reviewed;
it never backfills or fabricates unverified history.

The public host-deploy gateway separately enforces the fixed current public
pin, a fresh independently signed online highwater check *before* export use
and again after Host-signed live proof, and denies old key re-selection even
when the old Host can freshly sign a nonce. Local file rollback of both
public pin and private journal cannot lower an external highwater.

## Synthetic verification

- Protected installer source regression workflow runs Python 3.12/3.13
  and ephemeral root-owned fixtures for initial install, retained claims,
  simultaneous writers, signer/original STATE/source substitution, old key
  resurrection, staged publication failure and same-intent resume.
- Exact cross-owner workflow pins root-control graphical checkpoint issuer
  `9036c98e8af6469a17e8fcc31e1a40795330ee48` and host-deploy checkpoint
  consumer `7d052b340a026497fd32afb82d0a290d1d6bc60e` for one integrated
  synthetic external-CAS→protected installer→gateway test, coherent local
  rollback, retained remote highwater and missing caller override.

## Native acceptance remains NO-GO

The source-only `_install_source` accepts fixture dirfds and `checkpoint`
crash hooks; **it must never be exposed as a privileged RPC**. Neither the
synthetic original signed grant nor the root-owned attestation sample is an
approved production identity. Native Work must separately establish actual
original signer/Host enrollment, root-only immutable source/RECORD bytes,
real STATE identity, bootstrap/no-replacement pin installation, managed
external non-rollbackable issuer and UID-pinned relay, reboot/power-loss
recovery, independent current-owner epoch fencing at actual Host signing,
and operator approval. No real keys/Host/STATE/compiler authority are
activated by this source contract. The PR is intentionally draft.
