use super::*;

const SEALED_SEED_AD: &str = "gilgamesh.kms/v1/sealed-seed";
pub(crate) const KEK_SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;

/// Argon2id cost parameters for the outer (at-rest) KDF. Stored plaintext in
/// the vault header and covered by the header tag; enforced against
/// [`Argon2Params::MIN`] before any derivation to defeat downgrade.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::MIN
    }
}

impl Argon2Params {
    pub const MIN: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Inner-derivation parameters are fixed by the spec: they are part of the
    /// identity and can never change.
    pub(crate) const INNER: Self = Self::MIN;

    pub fn canonical(&self) -> String {
        format!(
            "m={},t={},p={}",
            self.memory_kib, self.iterations, self.parallelism
        )
    }

    pub fn validate(&self) -> Result {
        ensure!(
            self.memory_kib >= Self::MIN.memory_kib
                && self.iterations >= Self::MIN.iterations
                && self.parallelism >= Self::MIN.parallelism,
            "argon2 params `{}` below minimum `{}`",
            self.canonical(),
            Self::MIN.canonical(),
        );
        Ok(())
    }

    pub(crate) fn derive(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result {
        let params = argon2::Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(output.len()),
        )
        .map_err(|err| anyhow!("invalid argon2 params: {err}"))?;

        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(password, salt, output)
            .map_err(|err| anyhow!("argon2 derivation failed: {err}"))?;

        Ok(())
    }
}

pub(crate) fn seal(
    seed: &Seed,
    unlock_password: &str,
    params: &Argon2Params,
    kek_salt: &[u8; KEK_SALT_LEN],
    hardware_secret: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let kek = kek(unlock_password, params, kek_salt, hardware_secret)?;
    let nonce = random::<NONCE_LEN>()?;

    let mut ciphertext = XChaCha20Poly1305::new(Key::from_slice(&*kek))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed.as_bytes(),
                aad: SEALED_SEED_AD.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("failed to seal seed"))?;

    let mut sealed = nonce.to_vec();
    sealed.append(&mut ciphertext);

    Ok(sealed)
}

pub(crate) fn unseal(
    sealed: &[u8],
    unlock_password: &str,
    params: &Argon2Params,
    kek_salt: &[u8; KEK_SALT_LEN],
    hardware_secret: Option<&[u8; 32]>,
) -> Result<Seed> {
    ensure!(sealed.len() > NONCE_LEN, "sealed seed is truncated");
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);

    let kek = kek(unlock_password, params, kek_salt, hardware_secret)?;

    // A wrong password fails only via the Poly1305 tag; no other oracle.
    let mut plaintext = XChaCha20Poly1305::new(Key::from_slice(&*kek))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: SEALED_SEED_AD.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("wrong unlock password or corrupted vault"))?;

    let seed = plaintext
        .as_slice()
        .try_into()
        .map(Seed::from_bytes)
        .map_err(|_| anyhow!("sealed seed has invalid length"));
    plaintext.zeroize();

    seed
}

// AND-composition: hardware AND password, never hardware-only, so hardware
// compromise degrades to password-only strength, never worse.
fn kek(
    unlock_password: &str,
    params: &Argon2Params,
    kek_salt: &[u8; KEK_SALT_LEN],
    hardware_secret: Option<&[u8; 32]>,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut soft_kek = Zeroizing::new([0; 32]);
    params.derive(unlock_password.as_bytes(), kek_salt, &mut *soft_kek)?;

    match hardware_secret {
        Some(secret) => {
            let (kek, _) = Hkdf::<Sha256>::extract(Some(&*soft_kek), secret);
            Ok(Zeroizing::new(kek.into()))
        }
        None => Ok(soft_kek),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let params = Argon2Params::default();
        let kek_salt = [7; KEK_SALT_LEN];

        let sealed = seal(
            &Seed::from_bytes([0x42; 32]),
            "hunter22",
            &params,
            &kek_salt,
            None,
        )
        .unwrap();

        let seed = unseal(&sealed, "hunter22", &params, &kek_salt, None).unwrap();
        assert_eq!(seed.as_bytes(), &[0x42; 32]);

        assert!(unseal(&sealed, "hunter23", &params, &kek_salt, None).is_err());
    }

    #[test]
    fn hardware_secret_is_and_composed() {
        let params = Argon2Params::default();
        let kek_salt = [7; KEK_SALT_LEN];
        let secret = [9; 32];

        let sealed = seal(
            &Seed::from_bytes([0x42; 32]),
            "hunter22",
            &params,
            &kek_salt,
            Some(&secret),
        )
        .unwrap();

        let seed = unseal(&sealed, "hunter22", &params, &kek_salt, Some(&secret)).unwrap();
        assert_eq!(seed.as_bytes(), &[0x42; 32]);

        // Both factors are required: password alone, hardware alone with the
        // wrong password, or the wrong hardware secret must all fail.
        assert!(unseal(&sealed, "hunter22", &params, &kek_salt, None).is_err());
        assert!(unseal(&sealed, "hunter23", &params, &kek_salt, Some(&secret)).is_err());
        assert!(unseal(&sealed, "hunter22", &params, &kek_salt, Some(&[8; 32])).is_err());
    }

    #[test]
    fn params_below_minimum_are_rejected() {
        assert!(Argon2Params::default().validate().is_ok());
        assert!(
            Argon2Params {
                memory_kib: 32 * 1024,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Argon2Params {
                iterations: 2,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
