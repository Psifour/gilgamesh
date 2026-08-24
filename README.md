# gilgamesh

Deterministic key management. One memorized-or-written-down identity derives
every key you use — SSH, code signing, BIP39 wallets, application keys — and an
encrypted vault holds the few secrets that can't be derived. Lose every device
and every file: the identity alone recovers everything derived.

Implements the `gilgamesh.kms/v1` derivation spec ([design-doc.md](design-doc.md)).

## The model

```
raw entropy (coinflips / dice / file / CSPRNG)
  └─ seed = sha256(entropy)            ← 32-byte identity; the backup form
       └─ [+ optional derivation passphrase]
            └─ PRK  (Argon2id + HKDF)
                 ├─ ssh keys        gilgamesh ssh [keyname]
                 ├─ codesign keys
                 ├─ BIP39 wallets   gilgamesh mnemonic [keyname]
                 ├─ app keys        (library API, app/ namespace)
                 └─ vault keys      gilgamesh put/get/ls/rm
```

- **Derived keys are never stored.** They are recomputed on demand from the
  unlocked identity and exist only in locked, zeroized memory.
- **The vault file is ciphertext or public.** Back it up anywhere. It holds the
  sealed seed (working copy) and imported records under per-record
  XChaCha20-Poly1305.
- **The unlock password is changeable** — it only seals the seed at rest. The
  derivation passphrase is **immutable**: changing it is a migration to a new
  identity.
- **Recovery never requires the machine, the vault file, or any hardware.**
  The raw entropy (or its mnemonic form) plus the derivation passphrase, if
  any, is the complete identity.

## Install

```sh
cargo build --release                  # software-only
cargo build --release --all-features   # + TPM 2.0 (Linux/Windows), Secure Enclave (macOS)
```

Hardware backends:

| Platform | Feature | Backend | Notes |
|----------|---------|---------|-------|
| Linux    | `tpm`   | `/dev/tpmrm0` | needs read/write access (`tss` group) |
| Windows  | `tpm`   | TBS | |
| macOS    | `sep`   | Secure Enclave | binary must be code-signed with an App ID and keychain-access-groups entitlement |

## Quick start

```sh
# Create an identity. Flip a coin 128 times, or roll dice 50 times, or let the
# OS CSPRNG pick (prints a 24-word mnemonic — the ONLY backup of that identity):
gilgamesh init --ask-coinflips
gilgamesh init --random

# Verify your backup: restore into a scratch vault, compare fingerprints.
gilgamesh init --ask-mnemonic --vault /tmp/verify.vault
gilgamesh fingerprint

# Derive keys — same identity, same keys, on any machine, forever.
gilgamesh ssh                      # public key
gilgamesh ssh --private | ssh-add -  # never touches disk
gilgamesh ssh github               # independent named key
gilgamesh mnemonic                 # BIP39 wallet mnemonic

# Store secrets that can't be derived.
gilgamesh put api-token < token.txt
gilgamesh get api-token
gilgamesh ls
gilgamesh rm api-token

# Re-seal under a new unlock password (nothing downstream changes). The
# --kdf-* flags re-tune Argon2 at the same time.
gilgamesh change-password

# Bind the working copy to this machine's TPM/enclave. Requires attesting that
# the seed backup is verified: once bound, this vault file opens only here.
gilgamesh hardware status
gilgamesh hardware enable --backup-verified
gilgamesh hardware disable         # portable export: password-only again
```

The vault path defaults to `./gilgamesh.vault`; set `--vault` or
`GILGAMESH_VAULT`. Scripts can pass secrets via `GILGAMESH_PASSWORD`,
`GILGAMESH_PASSPHRASE`, and `GILGAMESH_NEW_PASSWORD` instead of prompts;
equivalent command-line flags exist but are hidden and warned about, because
argv leaks into shell history and `/proc/*/cmdline`.

## Agent

`gilgamesh agent` unlocks once and holds the identity for a session, so
nothing else has to prompt — and it speaks the ssh-agent protocol:

```sh
gilgamesh agent                    # foreground; prints the two socket paths
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/gilgamesh/agent.ssh.sock
ssh-add -l                         # your derived key(s), signed in-process:
ssh git@github.com                 # the private key never crosses a socket

gilgamesh agent status
gilgamesh agent lock               # drop the identity now
```

The identity locks after 15 idle minutes (`--timeout`, 0 to disable) and
re-prompts at the agent's terminal when next needed. A locked agent still
lists its public keys (`ssh-add -l`, `gilgamesh agent status`); only signing
needs the identity. Applications use the JSON socket
(`gilgamesh::agent::Client`) for app keys and vault records; wallet-seed
requests require confirmation at the agent's terminal unless started with
`--allow-wallet-seed`, and `--confirm-ssh` gates every ssh signature the same
way. The sockets must live in a private (0700) directory you own — the
default always is — or the agent refuses to start (`--allow-insecure-socket-dir`
overrides). Unix only for now.

## Passwords

At-rest protection is your unlock password's entropy plus ~22 bits of Argon2id
hardness (64 MB, 3 iterations by default; raise with `--kdf-memory 512
--kdf-iterations 4` at `init` — or later via `change-password` — where unlock
is per-session). The floor is five diceware words (~64 bits). Weaker passwords
warn and require explicit approval — the final say is always yours.

## Hardware binding

Hardware is AND-composed with the password: unlocking a bound vault needs
both, so hardware compromise degrades to password-only strength, never worse.
Hardware gates only the working copy, never the identity — recovery from the
entropy backup works with no hardware present. See
[SECURITY.md](SECURITY.md#hardware-binding) for what the TPM does *not* give
you (notably: no unlock rate limiting).

## Library

The CLI is a thin wrapper over the `gilgamesh` library crate: `EntropySource`,
`Identity`, `Vault`, `HardwareSealer`. Applications derive their own keys under
the reserved `app/` namespace via `Identity::derive_key` — system labels are
never handed out. Labels are append-only and frozen once shipped.

## Development

```sh
./bin/activate-hermit   # hermit-managed rust + just
just ci                 # clippy (deny warnings), cross-checks, fmt, tests
just ignored            # real-TPM roundtrip (needs /dev/tpmrm0 access)
```

swtpm-backed TPM tests run automatically when `swtpm` is installed; they are
skipped otherwise.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE)
or the [MIT license](LICENSE-MIT), at your option.

This software manages cryptographic keys and secrets. It is provided **as
is**, without warranty of any kind, and the authors accept **no
responsibility or liability** for any loss — of keys, funds, data, or access
— arising from its use. Read [SECURITY.md](SECURITY.md), keep your entropy
backup, and verify recovery before you depend on it.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
