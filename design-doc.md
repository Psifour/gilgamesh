# KMS Derivation Spec — `gilgamesh.kms/v1`

Namespace strings are opaque, immutable identifiers — never URLs. Append-only; never rename, reword, or repurpose a shipped label. All appended fields are joined with `/`; appended field values must not contain `/`.

## Secrets and roles

```
raw_entropy_input      entropy source, canonically encoded (see Encodings)
seed                   = sha256(raw_entropy_input)          // 32B canonical identity; backup form
unlock_password        CHANGEABLE; used only to seal the seed at rest (KEK); never in derivation
derivation_passphrase  optional, IMMUTABLE; part of identity if used; changing it = new identity (migration)
```

Identity = `seed [+ derivation_passphrase]`. Recovery never requires the machine, the vault file, or any hardware.

## Derivation (inner; deterministic identity → keys)

```
argon2_salt = truncate16(sha256("gilgamesh.kms/v1/argon2-salt/" || seed))
PRK         = hkdf_extract(salt = argon2id(derivation_passphrase | "", argon2_salt, 64MB, 3, 1),
                           ikm  = seed)
```

Nested:

```
PRK = hkdf_extract(
        argon2id(derivation_passphrase,
                 truncate16(sha256("gilgamesh.kms/v1/argon2-salt/" || sha256(raw_entropy_input))),
                 64MB, 3, 1),
        sha256(raw_entropy_input))
```

## Derivation paths (independent; add labels freely, never modify existing)

```
ssh_seed      = hkdf_expand(PRK, "gilgamesh.kms/v1/ssh-ed25519/"   || keyname, 32)
codesign_seed = hkdf_expand(PRK, "gilgamesh.kms/v1/codesign/"      || keyname, 32)
btc_entropy   = hkdf_expand(PRK, "gilgamesh.kms/v1/bip39-entropy/" || keyname, 32)   // keyname default: "default"
vault_key     = hkdf_expand(PRK, "gilgamesh.kms/v1/vault-key",                32)
mac_key       = hkdf_expand(PRK, "gilgamesh.kms/v1/mac-key",                  32)
app_key       = hkdf_expand(PRK, "gilgamesh.kms/v1/app/"           || label,  32)    // application-defined
```

Labels directly under the namespace root are **system paths**, reserved for the KMS itself. Application/runtime derivation must live under `app/`: the two spaces can never collide, and a derivation path's trust domain is legible from its label. The public derivation API hands out `app/` labels only — system keys (`vault-key`, `mac-key`, ...) are never derivable through it.

## Downstream keys

```
ssh_keypair = ed25519_from_seed(ssh_seed)
wallet      = bip32_master(bip39_seed(bip39_mnemonic(btc_entropy), passphrase = ""))
```

BIP39 passphrase always empty; exported SSH keys never encrypted under any system password (export to ssh-agent, ephemeral files, or vault).

## At-rest sealing (outer; envelope encryption)

The seed exists on disk only sealed. Unlock: password → KEK → decrypt seed → derive in memory → zeroize on lock/timeout/suspend.

```
kek_salt    = random16()                                              // stored plaintext in header
soft_kek    = argon2id(unlock_password, kek_salt, 64MB, 3, 1)

// hardware binding (default ON when TPM/enclave present AND seed backup verified):
KEK         = hkdf_extract(salt = soft_kek, ikm = tpm_unseal(tpm_blob))   // AND-composition
// software-only / portable export:
KEK         = soft_kek

sealed_seed = nonce || xchacha20poly1305_encrypt(KEK, nonce, "gilgamesh.kms/v1/sealed-seed", seed)
```

Rules:
- Hardware AND password, never hardware-only. Hardware compromise degrades to password-only, never worse.
- Prefer enclave/fTPM over discrete TPM. Seal to storage hierarchy, not PCRs (PCR-binding is paranoid opt-in). vTPMs are not equivalent protection.
- Refuse to enable hardware binding until seed backup is fingerprint-verified.
- Hardware may gate the working copy, never the identity: recovery path never depends on any TPM existing.
- Password change = re-seal seed under new KEK; nothing downstream rotates. Outer argon2 params change the same way — a re-seal — but re-binds `header_tag`, so it requires the unlocked identity (and thus the derivation passphrase, if set). derivation_passphrase change = migration (new identity, move funds, re-enroll).
- Wrong password fails via Poly1305 tag; no other oracle.

**Known limitation — no TPM anti-hammering.** The sealed object uses empty auth with `NO_DA`: the TPM is a machine-binding factor only and provides zero rate limiting. An attacker with OS access to the bound machine can unseal the hardware secret freely; brute-force resistance then rests entirely on the password's Argon2 cost (i.e., the vault degrades to software-only strength, as designed — but users must not assume "TPM = lockout"). Fixing this means sealing under a password-derived authValue without `NO_DA`, so failed unseals hit the TPM's dictionary-attack lockout. That is deferred deliberately: (a) it changes the KEK/auth derivation and the sealed-blob wire format, breaking every existing hardware-bound vault (re-enroll required, so it must ship as a versioned `tpm2-blob/v2`); (b) with plain password sessions the authValue crosses the bus in cleartext on a discrete TPM — doing it right needs HMAC sessions (salted, bound), which is a substantial protocol addition; (c) DA lockout state is TPM-global and can collaterally lock out other TPM users. On discrete TPMs, note also that the unsealed secret itself crosses the bus in cleartext (no parameter encryption): prefer fTPM/enclave, where there is no bus to interpose.

At-rest strength = unlock_password entropy + ~22 bits (Argon2id 64MB vs GPU). Floor: ≥5 diceware words (~64 bits raw). Below ~40 bits raw, at-rest protection is theater. Raising memory to 512MB/t=4 buys ~3 more bits and is recommended where unlock is per-session (`--kdf-memory 512 --kdf-iterations 4`, at `init` or later via `change-password`). The CLI warns below an estimated ~64 bits and requires explicit approval (y/N or `--allow-weak-password`); the user always keeps the final say.

## Vault (XChaCha20-Poly1305, per-record)

```
nonce  = random24()                                   // per record; stored plaintext (required, safe)
ad     = record_id || "/" || record_type
record = nonce || xchacha20poly1305_encrypt(vault_key, nonce, ad, plaintext_secret)
```

## Header integrity

```
header_tag  = hmac_sha256(mac_key, version || "/" || argon2_params)
records_tag = hmac_sha256(mac_key, "gilgamesh.kms/v1/records-tag"
                                   || for each record: len64le(id) || id
                                                    || len64le(type) || type
                                                    || len64le(bytes) || bytes)
```

On load: enforce minimum acceptable argon2 params before derivation; verify `header_tag` after derivation (defeats parameter downgrade; hard failure).

`records_tag` is refreshed by every put/rm and verified on unlock, **warn-only**: external mutation of the record set is permitted, but silent deletion, reordering, or rollback of records relative to the stored tag must not pass unremarked. A missing tag (older vault, external tooling) warns that deletion cannot be detected.

**Known limitation — whole-file rollback is undetectable.** The tag lives inside the file it protects: replacing the entire vault with an older, internally consistent version passes verification silently. Detecting that requires an anchor outside the file — a TPM NV monotonic counter for hardware-bound vaults, or the user recording the current tag out of band. Until such an anchor ships, `records_tag` guarantees only that the record set and its tag were written together.

## Persisted state

```
vault_file = version || argon2_params || kek_salt || [tpm_blob] || sealed_seed || header_tag || records[] || records_tag
```

Mutations serialize on an advisory exclusive lock held on a sibling lock file (locking the vault itself would be defeated by the atomic-rename store); readers need no lock. Without it, concurrent load-modify-store cycles silently lose writes.

All ciphertext or public. Everything derived is recomputable from identity. Imported (non-derived) secrets exist only in the vault: back it up (ciphertext; safe anywhere). Hardware-bound working copies are non-portable; portable export uses software-only sealing.

## Encodings (canonical; exact bytes are load-bearing)

```
coinflips : ASCII "0"/"1", one char per flip, no separators
dice      : ASCII "1"–"6", one char per roll, no separators
file      : raw bytes, bit-exact
mnemonic  : BIP39 mnemonic; canonical bytes are the decoded entropy (entry convenience for `file`, not a new encoding)
```

Minimum ~128 bits source entropy (e.g., ≥128 flips, ≥50 rolls). Display seed fingerprint at creation and restore for verification. The fingerprint covers the seed only, never derivation_passphrase: prompted passphrases are double-entry confirmed at creation, and verifying a passphrase across restores requires comparing a derived public key.

CSPRNG creation (`--random`) prints the 32 entropy bytes once as a 24-word mnemonic: that mnemonic is the identity's only backup and re-enters through the `mnemonic` form. It requires explicit confirmation (the user cannot audit CSPRNG entropy the way they can coinflips).

## Invariants

- unlock_password appears in exactly one primitive (outer argon2id) and is changeable; derivation_passphrase is immutable and appears in exactly one primitive (inner argon2id). Neither is ever a BIP39 passphrase, SSH passphrase, salt, or key elsewhere.
- Plaintext seed and derived keys exist only in locked, zeroizable memory with a bounded unlock lifetime.
- Hardware binding: AND-composed, working-copy only, backup-verified first, never required for recovery.
- Labels and encodings are append-only and frozen once shipped. Appended fields join with `/` and must not contain `/`.
- Nonce uniqueness per key is required; 24B random nonces satisfy it. Nonces/salts are public.
- Same `(info, length)` prefix rule: new key ⇒ new label, not new length.

## Agent

`gilgamesh agent` holds one unlocked identity for a session so client
applications (password manager, wallet, ssh) never see the password and never
hold key material longer than one operation. One agent per vault file.

- Lifecycle: unlocks on start; holds `Identity` (mlock'd, zeroize-on-drop)
  with an idle timeout (default 900s; `--timeout 0` disables). On timeout or
  `lock` the identity is dropped; an agent running on a terminal re-prompts
  on the next request needing it, a non-interactive one refuses. Lock on
  suspend is a TODO (needs a platform suspend signal).
- Transport: Unix socket at `$XDG_RUNTIME_DIR/gilgamesh/agent.sock`
  (`$TMPDIR/gilgamesh-{uid}/` fallback; dir 0700, socket 0600 from birth via
  umask; Windows named-pipe transport not yet implemented). The socket
  directory must be 0700 and owned by the user, or the agent refuses to
  start (`--allow-insecure-socket-dir` → warning): clients never
  authenticate the agent, so the directory owner could swap the socket. A
  non-socket at the socket path is never replaced; a stale socket is. Every
  connection's peer uid must equal the agent's before any frame is read.
  Frames are u32-BE-length-prefixed JSON, capped at 4 MiB, many per
  connection.
- Operations: `status` (state plus the served ssh public keys, available
  while locked), `lock`, `derive_app_key(label)` (`app/` namespace
  enforced exactly as `Identity::derive_key`), `vault_list` / `vault_get` /
  `vault_put` / `vault_rm`, `wallet_seed(keyname)`. Vault operations reload
  the file each time (mutations under `.vault.lock`) and verify the loaded
  vault against the held identity's header tag, so a swapped vault file is
  refused, not corrupted.
- `wallet_seed` hands out non-app derived key material, so it requires
  per-request interactive confirmation at the agent's terminal by default
  (`--allow-wallet-seed` disables — warn-and-approve, the user keeps the
  final say).
- Never exposed over the socket: the seed, the derivation passphrase, system
  labels (`vault-key`, `mac-key`, ...), or raw ssh/codesign private keys.
- SSH: the agent also speaks the ssh-agent wire protocol on a sibling socket
  (`agent.ssh.sock`; point `SSH_AUTH_SOCK` or a per-host `IdentityAgent` at
  it). It lists derived ssh keys (`--ssh-key`, repeatable; default
  `default`) from public halves cached at startup — so a locked agent still
  answers `ssh-add -l` without a re-unlock prompt — and answers sign
  requests in-process: private keys never cross any socket — clients
  receive signatures only. `--confirm-ssh` gates every signature on terminal
  approval (the `ssh-add -c` posture).
- Client side: `gilgamesh::agent::Client` (library), `gilgamesh agent
  status` / `gilgamesh agent lock` (CLI). Secrets crossing the JSON socket
  ride in zeroized buffers on both ends, best-effort (serializer internals
  are outside zeroize's reach, like the transient stack copies documented in
  the memory-hygiene notes).

## Additional Wants

- Deadman Switch/Canary
