# Cryptographic design

* **Hash:** SHA-256, own implementation of a public standard (`lib/sha256.c`), tested against NIST vectors incl. 1M×'a'.
* **Signatures:** Ed25519 (RFC 8032) via vendored **Monocypher 4.0.2** (`third_party/monocypher`), tested against an RFC 8032
  vector. No project-written public-key crypto. Constant-time hash comparison via `crypto_verify32`.
* **Hierarchy:** `root` (certifies only) → role keys `fw` (Stage 2), `uefi`, `os` (kernel), `dtb`. Certificate message =
  `"QVKEY\1" ‖ key_id ‖ role ‖ pubkey`, signed by root. Role must equal the image type's role.
* **Key handling:** keys are generated into `keys/` (git-ignored, mode 600) by `scripts/gen_keys.sh`. Only
  `root.pub` enters firmware (`build/generated/root_pubkey.h`). Private keys never enter the repository or images.
  The release workflow uses **ephemeral CI test keys** (see SECURITY.md).
* **Revocation:** signer key IDs and payload SHA-256 values in the store's deny-lists. The lists are *not* themselves
  signed; they inherit the (simulated) trust of the store.
* **Not implemented:** key rotation policy, certificate expiry, hardware key storage, constant-time guarantees beyond
  Monocypher's, algorithm agility (the `hash_alg`/`sig_alg` fields are checked; exactly one value is accepted).
* **Verification order caveat:** all three checks always run (complete diagnostics); the verdict is their conjunction.
  This is a deliberate trade for observability; it does not change what is accepted.
