# Archive provider actual consumer source integration — 2026-11-03

This candidate composes host-install PR #21 with archive-mirror `9df811cf9315efec4312e6a16738a23149d286a2` and canonical host-identify `59dbc181f54c6ac29ee5eb1f83b6f322fb73c037`. Only archive-mirror purpose `archive-mirror-upstream-fetch`, not Cloudflare issuer, is accepted.

The receiving owner verifies signed current authorization, Host HTTPS nonce and delivery, then **fsyncs an irreversible `installing` state BEFORE the first actual archive-mirror `install_verified` call**. An interrupted/lost response leaves `installing`: no automatic redelivery, even of identical bytes, on reboot. Only separately protected native installed-byte/identity witness plus exact consumer inspection permits a canonical terminal receipt through `record_receipt`. Source tests invoke actual archive-mirror Python `install_verified` and `apply_signed_revocation` on isolated synthetic values and locations.

Revocation must first durably enter the receiving owner's `revoked` state and only then call archive-mirror signed revocation, which writes a private tombstone. An uncertain outcome holds and cannot reopen provider secret; retained archive objects and pins are unaffected. The receiving owner never supplies the archive download JWT grants or issuer-only Cloudflare access.

**Native installation HOLD**: no real HTTPS listener, provider credential, current revocation service, protected installation identity/STATE, archive application installed-byte attester, UID/GID or cross-owner source pin selection. The native witness callback provided for synthetic tests is not a native witness. The app and issuer public keys must be independently installed and pinned before enabling. No installed service or production authority changed.
