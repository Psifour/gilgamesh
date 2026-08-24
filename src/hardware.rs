use super::*;

/// A hardware secret-wrapping backend (TPM, enclave). Hardware binding is
/// AND-composed with the unlock password and gates only the working copy of
/// the seed, never the identity: recovery must always be possible from the
/// entropy backup alone, with no hardware present.
pub trait HardwareSealer {
    /// Wrap a fresh hardware secret. The returned blob is stored plaintext in
    /// the vault header and is useless off this machine.
    fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>>;

    /// Recover the hardware secret from a stored blob.
    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>>;

    /// What this backend actually is (e.g. "fTPM (INTC)"). Surfaced so users
    /// can apply the spec's preference order: enclave/fTPM over discrete TPM;
    /// vTPMs are not equivalent protection.
    fn describe(&self) -> String;
}

/// Open this platform's default hardware backend: the kernel-managed TPM on
/// Linux, TBS on Windows, the Secure Enclave on macOS.
pub fn platform_sealer() -> Result<Box<dyn HardwareSealer>> {
    #[cfg(all(any(target_os = "linux", windows), feature = "tpm"))]
    return Ok(Box::new(tpm::TpmSealer::open()?));

    #[cfg(all(target_os = "macos", feature = "sep"))]
    return Ok(Box::new(sep::SepSealer::open()?));

    #[allow(unreachable_code)]
    Err(anyhow!(
        "this gilgamesh build has no hardware backend for this platform; rebuild with \
         `--features tpm` (Linux/Windows TPM 2.0) or `--features sep` (macOS Secure Enclave)"
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const MAGIC: &[u8] = b"mock-sealed/";

    /// XOR "sealer" standing in for a TPM in tests.
    pub(crate) struct MockSealer {
        pub(crate) key: u8,
    }

    impl HardwareSealer for MockSealer {
        fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>> {
            let mut blob = MAGIC.to_vec();
            blob.extend(secret.iter().map(|byte| byte ^ self.key));
            Ok(blob)
        }

        fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            let wrapped: &[u8; 32] = blob
                .strip_prefix(MAGIC)
                .and_then(|wrapped| wrapped.try_into().ok())
                .ok_or_else(|| anyhow!("mock sealer cannot unseal this blob"))?;

            let mut secret = Zeroizing::new([0; 32]);
            for (out, byte) in secret.iter_mut().zip(wrapped) {
                *out = byte ^ self.key;
            }

            Ok(secret)
        }

        fn describe(&self) -> String {
            "mock sealer".into()
        }
    }
}
