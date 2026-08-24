# Security

This document describes what gilgamesh protects, what it deliberately does
not, and the known limitations of the current implementation. The normative
derivation spec is [design-doc.md](design-doc.md).

## Reporting a vulnerability

Email <outdatedconcept@gmail.com>. Please do not open public issues for
exploitable vulnerabilities before a fix ships. There is no bug bounty.

gilgamesh is pre-1.0. The derivation spec (`gilgamesh.kms/v1` labels,
encodings, and formulas) is frozen and append-only; everything else may change.

## Cryptography

| Purpose | Construction |
|---------|--------------|
| Identity seed | `sha256(raw_entropy_input)` over canonical encodings |
| Inner KDF (identity → PRK) | Argon2id (64 MB, t=3, p=1, fixed) + HKDF-SHA256 extract |
| Key derivation | HKDF-SHA256 expand under frozen, namespaced labels |
| At-rest sealing (KEK) | Argon2id (≥64 MB, t≥3; user-raisable) over the unlock password |
| Hardware AND-composition | `KEK = HKDF-extract(salt = soft_kek, ikm = hardware_secret)` |
| Seed + record encryption | XChaCha20-Poly1305, 24-byte random nonces, label/id AD |
| Header + record-set integrity | HMAC-SHA256 under a derived `mac-key` |
| Signing keys | Ed25519 (SSH, code signing) |

All primitives come from the RustCrypto crates plus `ed25519-dalek`.

## Threat model

**Protected against:**

- **Theft of the vault file.** Everything in it is ciphertext or public.
  Cracking it costs a password brute-force through Argon2id (~22 bits of
  hardness on top of the password's entropy). With hardware binding, the file
  is additionally useless off the bound machine.
- **KDF parameter downgrade.** Minimum Argon2 parameters are enforced before
  any derivation; the header is HMAC-verified after unlock.
- **Sealed-seed or record tampering.** AEAD authentication fails closed; a
  wrong password is indistinguishable from tampering (Poly1305 tag only, no
  other oracle).
- **Silent record deletion or reordering** relative to the stored record-set
  tag (warn-only by design: external tooling may legitimately edit the vault,
  but it must not pass unremarked).
- **Loss of every device and file.** The entropy backup (plus the derivation
  passphrase, if any) regenerates all derived keys with no hardware, no vault
  file, and no gilgamesh-specific state.

**Not protected against:**

- **A compromised host while unlocked.** Anything that can read the process's
  memory or drive the CLI gets the unlocked identity. This is out of scope for
  any software KMS.
- **A weak unlock password.** Below ~40 bits of real entropy, at-rest
  protection is theater. The CLI warns below an estimated ~64 bits and
  requires explicit approval; the estimate is a crude upper bound.
- **Whole-file rollback.** `records_tag` lives inside the file it protects:
  replacing the entire vault with an older, internally consistent copy passes
  verification. Detection needs an external anchor (a TPM NV monotonic
  counter is the planned fix; until then, note the tag out of band if this
  matters to you).
- **A misremembered derivation passphrase.** The fingerprint identifies the
  seed only: restoring with a wrong passphrase reproduces a matching
  fingerprint but a different identity with different keys. Prompted
  passphrases are confirmed by double entry at creation; to verify a
  passphrase across restores, compare a derived public key (e.g.
  `gilgamesh ssh`).
- **Forgetting the identity.** There is no escrow. Losing the entropy backup
  (or an immutable derivation passphrase) loses every derived key permanently.

## Hardware binding

Binding seals a random 32-byte hardware secret to the platform TPM 2.0
(storage hierarchy, not PCRs) or the macOS Secure Enclave, and folds it into
the KEK **in AND-composition with the password** — never hardware-only, so a
broken TPM degrades the vault to ordinary password protection, never worse.
Binding is refused until you attest the seed backup is fingerprint-verified,
because a lost or reset device makes the bound vault file permanently
undecryptable.

Know what the TPM does **not** provide here:

- **No anti-hammering.** The sealed object uses empty auth with `NO_DA`: the
  TPM is a machine-binding factor only and rate-limits nothing. An attacker
  with OS access to the bound machine can query the TPM freely; brute-force
  resistance rests entirely on the password. (Password-derived TPM auth with
  dictionary-attack lockout is deferred; it requires a new blob format and
  HMAC sessions.)
- **Discrete TPMs expose the bus.** No parameter encryption is used: on a
  discrete TPM the unsealed hardware secret crosses the bus in cleartext.
  Prefer fTPM or the Secure Enclave, where there is no bus to interpose.
- **vTPMs are not equivalent protection** — the hypervisor holds the seed.

## Secrets in memory and process metadata

- The unlocked identity lives in an `mlock`ed (best-effort), zeroize-on-drop
  heap allocation, excluded from core dumps on Linux. Transient stack copies
  during derivation are zeroized promptly but cannot be fully guaranteed
  against; swap and hibernation of those transients are residual risks where
  `mlock` fails (e.g. tight `RLIMIT_MEMLOCK` in containers).
- Passwords, passphrases, mnemonics, and raw entropy are held in zeroizing
  buffers throughout, including clap-parsed values.
- Secret-valued command-line flags are hidden from `--help` and warned about
  when used: argv is visible in shell history and `/proc/*/cmdline`, and
  environment variables are visible to same-user processes. Interactive
  prompts are the safe path.
- Vault writes are atomic (0600 temp file, fsync, rename, directory fsync).
  On Windows no explicit DACL is set; the file inherits the parent
  directory's ACLs, which in a user profile restrict access to the user.

## Agent

`gilgamesh agent` trades a longer identity lifetime for fewer password
entries: one process holds the unlocked `Identity` (same mlock/zeroize
handling) and serves local clients over two sockets — length-prefixed JSON,
and the ssh-agent protocol.

- Authentication is the peer's uid: any process running as you can use the
  agent while it is unlocked. That is the same trust model as `ssh-agent`,
  and it is the point of the uid check — with Yama-style ptrace restrictions,
  same-uid processes cannot necessarily read each other's memory, so the
  socket boundary is real. The sockets are 0600 inside a 0700 directory.
- Clients do not authenticate the agent. Whoever controls the socket
  directory can replace the socket with their own and receive what clients
  send (record plaintext on `vault_put`), so the agent refuses to serve from
  a directory that is not 0700 and owned by the user, and refuses to replace
  anything at the socket path that is not a socket. `--allow-insecure-socket-dir`
  downgrades the first refusal to a warning.
- Public ssh keys are computed at startup and served while locked (listing
  a key is not a use of the identity); signing, app keys, records, and the
  wallet seed all require the unlocked identity.
- The agent never serves the seed, the derivation passphrase, system
  derivation labels, or raw ssh/codesign private keys. SSH clients receive
  signatures only. The wallet seed — the one derived secret beyond `app/`
  keys — requires per-request confirmation at the agent's terminal unless
  explicitly waived (`--allow-wallet-seed`); `--confirm-ssh` adds the same
  gate to every signature.
- The idle timeout (default 900s) drops the identity; malware that arrives
  while the agent is unlocked wins anyway (see the threat model), so the
  timeout bounds exposure, it does not prevent it.

## Verification status

- Software paths and swtpm-backed TPM tests run in CI on Linux.
- The Linux TPM backend has passed a real-hardware roundtrip.
- The Windows (TBS) and macOS (Secure Enclave) backends are compile-checked
  for their targets but have **not** been exercised on real hardware yet.
  Treat them as beta.
