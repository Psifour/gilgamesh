pub use {
    bip39, ed25519_dalek,
    entropy::EntropySource,
    hardware::HardwareSealer,
    identity::{Identity, Seed},
    seal::Argon2Params,
    vault::{Record, RecordsIntegrity, Vault},
    zeroize::Zeroizing,
};

use {
    anyhow::{Context, Error, anyhow, bail, ensure},
    argon2::Argon2,
    arguments::Arguments,
    base64::{Engine, engine::general_purpose::STANDARD as BASE64},
    bip39::Mnemonic,
    chacha20poly1305::{
        Key, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    },
    clap::{Args, Parser},
    ed25519_dalek::SigningKey,
    hkdf::Hkdf,
    hmac::{Hmac, Mac},
    options::Options,
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    sha2::{Digest, Sha256},
    ssh_key::{
        LineEnding, PrivateKey,
        private::{Ed25519Keypair, KeypairData},
    },
    std::{
        env, fmt, fs,
        io::{self, IsTerminal, Read, Write},
        path::PathBuf,
        process,
    },
    zeroize::{Zeroize, ZeroizeOnDrop},
};

#[cfg(unix)]
pub mod agent;
mod arguments;
pub mod entropy;
pub mod hardware;
pub mod identity;
mod options;
pub mod seal;
#[cfg(all(target_os = "macos", feature = "sep"))]
pub mod sep;
mod subcommand;
#[cfg(feature = "tpm")]
pub mod tpm;
pub mod vault;

/// Namespace prefix for every derivation label. Labels are append-only and
/// frozen once shipped; never rename, reword, or repurpose one.
pub const NAMESPACE: &str = "gilgamesh.kms/v1";

/// Sub-namespace for application-defined derivation labels. Everything
/// directly under [`NAMESPACE`] is reserved for the KMS itself (system paths:
/// ssh, codesign, bip39, vault-key, mac-key, ...); runtime and application
/// derivation lives under this prefix so the two can never collide.
pub const APP_NAMESPACE: &str = "gilgamesh.kms/v1/app/";

pub type Result<T = (), E = Error> = std::result::Result<T, E>;

type HmacSha256 = Hmac<Sha256>;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn labeled_sha256(label: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Filter an untrusted string for terminal display: graphic ASCII and spaces
/// pass, everything else — control bytes, escape sequences, non-ASCII —
/// becomes `?`. Record ids and types come from an externally editable file
/// and must not be able to smuggle escape sequences to the terminal.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("system entropy source failed: {err}"))?;
    Ok(bytes)
}

/// Best-effort pinning of long-lived secrets: lock their pages against swap
/// (and exclude them from core dumps on Linux). Failures are ignored —
/// RLIMIT_MEMLOCK may be low in containers — because zeroize-on-drop still
/// applies either way; transient stack copies are outside its reach and are
/// zeroized promptly instead.
pub(crate) mod memlock {
    #[cfg(unix)]
    pub(crate) fn lock(ptr: *const u8, len: usize) {
        unsafe {
            libc::mlock(ptr.cast(), len);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_DONTDUMP);
        }
    }

    #[cfg(unix)]
    pub(crate) fn unlock(ptr: *const u8, len: usize) {
        unsafe {
            libc::munlock(ptr.cast(), len);
        }
    }

    #[cfg(windows)]
    pub(crate) fn lock(ptr: *const u8, len: usize) {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(ptr.cast(), len);
        }
    }

    #[cfg(windows)]
    pub(crate) fn unlock(ptr: *const u8, len: usize) {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(ptr.cast(), len);
        }
    }
}

pub(crate) mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let string = String::deserialize(deserializer)?;
        BASE64.decode(&string).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod b64_opt {
    use super::*;

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&BASE64.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|string| BASE64.decode(&string).map_err(serde::de::Error::custom))
            .transpose()
    }
}

pub fn main() {
    let args = Arguments::parse();

    if let Err(err) = args.run() {
        eprintln!("error: {err}");

        for (i, cause) in err.chain().skip(1).enumerate() {
            if i == 0 {
                eprintln!();
                eprintln!("because:");
            }
            eprintln!("- {cause}");
        }

        if env::var_os("RUST_BACKTRACE")
            .map(|val| val == "1")
            .unwrap_or_default()
        {
            eprintln!();
            eprintln!("{}", err.backtrace());
        }

        process::exit(1);
    }
}
