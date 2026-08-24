use super::*;

// Frozen labels: append-only, never modify a shipped one. New key => new
// label, never a new length under the same label.
pub(crate) const ARGON2_SALT_LABEL: &str = "gilgamesh.kms/v1/argon2-salt/";
const BIP39_LABEL: &str = "gilgamesh.kms/v1/bip39-entropy/";
const CODESIGN_LABEL: &str = "gilgamesh.kms/v1/codesign/";
const FINGERPRINT_LABEL: &str = "gilgamesh.kms/v1/fingerprint/";
const MAC_KEY_LABEL: &str = "gilgamesh.kms/v1/mac-key";
const SSH_LABEL: &str = "gilgamesh.kms/v1/ssh-ed25519/";
const VAULT_KEY_LABEL: &str = "gilgamesh.kms/v1/vault-key";

/// The 32-byte canonical identity (`sha256(raw_entropy_input)`). This is the
/// backup form: recovery never requires the machine, the vault file, or any
/// hardware.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short public fingerprint for backup verification at creation/restore.
    pub fn fingerprint(&self) -> String {
        hex(&labeled_sha256(FINGERPRINT_LABEL, &self.0)[..8])
    }
}

/// Unlocked identity: seed plus the PRK from the inner derivation. Identity is
/// `seed [+ derivation_passphrase]`; the passphrase is immutable and changing
/// it is a migration to a new identity. Construction runs Argon2id (64MB) and
/// should happen once per unlock; drop to lock.
///
/// The secrets live in a heap allocation that is mlocked (best-effort) for the
/// identity's lifetime, then zeroized before the pages are unlocked and freed.
pub struct Identity {
    secrets: Box<Secrets>,
}

struct Secrets {
    seed: Seed,
    prk: Prk,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Prk([u8; 32]);

impl Drop for Identity {
    fn drop(&mut self) {
        // Zeroize while the pages are still locked; the fields' own
        // zeroize-on-drop then re-zeroizes zeros harmlessly when the box frees.
        self.secrets.seed.zeroize();
        self.secrets.prk.zeroize();
        memlock::unlock(
            std::ptr::from_ref(&*self.secrets).cast(),
            size_of::<Secrets>(),
        );
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn new(seed: Seed, derivation_passphrase: Option<&str>) -> Result<Self> {
        let salt = &labeled_sha256(ARGON2_SALT_LABEL, seed.as_bytes())[..16];

        let mut stretched = Zeroizing::new([0; 32]);
        Argon2Params::INNER.derive(
            derivation_passphrase.unwrap_or("").as_bytes(),
            salt,
            &mut *stretched,
        )?;

        let (prk, _) = Hkdf::<Sha256>::extract(Some(&*stretched), seed.as_bytes());

        let secrets = Box::new(Secrets {
            seed,
            prk: Prk(prk.into()),
        });
        memlock::lock(std::ptr::from_ref(&*secrets).cast(), size_of::<Secrets>());

        Ok(Self { secrets })
    }

    pub fn seed(&self) -> &Seed {
        &self.secrets.seed
    }

    pub fn fingerprint(&self) -> String {
        self.secrets.seed.fingerprint()
    }

    /// Expand an application-defined label into a 32-byte key. The label must
    /// live under [`APP_NAMESPACE`]: labels directly under [`NAMESPACE`] are
    /// system paths (vault-key, mac-key, ssh, ...) and are never handed out
    /// here. Add new labels freely, never modify existing ones.
    pub fn derive_key(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(
            label
                .strip_prefix(APP_NAMESPACE)
                .is_some_and(|rest| !rest.is_empty()),
            "label must start with `{APP_NAMESPACE}` (system labels are reserved)"
        );
        Ok(self.expand(label))
    }

    pub fn ssh_seed(&self, keyname: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.keyed(SSH_LABEL, keyname)
    }

    /// Exported SSH keys are never encrypted under any system password; export
    /// to ssh-agent, ephemeral files, or the vault.
    pub fn ssh_keypair(&self, keyname: &str) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(&*self.ssh_seed(keyname)?))
    }

    pub fn codesign_seed(&self, keyname: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.keyed(CODESIGN_LABEL, keyname)
    }

    pub fn codesign_keypair(&self, keyname: &str) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(&*self.codesign_seed(keyname)?))
    }

    pub fn bip39_entropy(&self, keyname: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.keyed(BIP39_LABEL, keyname)
    }

    pub fn bip39_mnemonic(&self, keyname: &str) -> Result<Zeroizing<Mnemonic>> {
        Ok(Zeroizing::new(Mnemonic::from_entropy(
            &*self.bip39_entropy(keyname)?,
        )?))
    }

    /// BIP39 seed for `bip32_master`; the BIP39 passphrase is always empty.
    pub fn wallet_seed(&self, keyname: &str) -> Result<Zeroizing<[u8; 64]>> {
        Ok(Zeroizing::new(self.bip39_mnemonic(keyname)?.to_seed("")))
    }

    pub(crate) fn vault_key(&self) -> Zeroizing<[u8; 32]> {
        self.expand(VAULT_KEY_LABEL)
    }

    pub(crate) fn mac_key(&self) -> Zeroizing<[u8; 32]> {
        self.expand(MAC_KEY_LABEL)
    }

    fn keyed(&self, label: &str, keyname: &str) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(!keyname.is_empty(), "keyname must not be empty");
        ensure!(!keyname.contains('/'), "keyname must not contain '/'");
        Ok(self.expand(&format!("{label}{keyname}")))
    }

    fn expand(&self, info: &str) -> Zeroizing<[u8; 32]> {
        let hkdf =
            Hkdf::<Sha256>::from_prk(&self.secrets.prk.0).expect("PRK is a valid HKDF-SHA256 key");
        let mut okm = Zeroizing::new([0; 32]);
        hkdf.expand(info.as_bytes(), &mut *okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> Identity {
        Identity::new(Seed::from_bytes([0x42; 32]), None).unwrap()
    }

    #[test]
    fn derivation_is_deterministic_and_passphrase_separates_identities() {
        let without = test_identity();
        let same = test_identity();
        let with = Identity::new(Seed::from_bytes([0x42; 32]), Some("passphrase")).unwrap();

        assert_eq!(
            *without.ssh_seed("default").unwrap(),
            *same.ssh_seed("default").unwrap()
        );
        assert_ne!(
            *without.ssh_seed("default").unwrap(),
            *with.ssh_seed("default").unwrap()
        );
        assert_eq!(without.fingerprint(), with.fingerprint());
    }

    #[test]
    fn paths_and_keynames_are_independent() {
        let identity = test_identity();

        let ssh = identity.ssh_seed("default").unwrap();
        assert_ne!(*ssh, *identity.codesign_seed("default").unwrap());
        assert_ne!(*ssh, *identity.bip39_entropy("default").unwrap());
        assert_ne!(*ssh, *identity.ssh_seed("github").unwrap());
        assert_ne!(*identity.vault_key(), *identity.mac_key());

        assert!(identity.bip39_mnemonic("default").is_ok());
    }

    #[test]
    fn keynames_and_labels_are_validated() {
        let identity = test_identity();

        assert!(identity.ssh_seed("").is_err());
        assert!(identity.ssh_seed("with/slash").is_err());
        assert!(
            identity
                .derive_key("gilgamesh.kms/v1/app/x25519/peer")
                .is_ok()
        );
        assert!(
            identity.derive_key("gilgamesh.kms/v1/app/").is_err(),
            "an empty app label must be rejected"
        );
        assert!(
            identity.derive_key("gilgamesh.kms/v1/x25519/peer").is_err(),
            "labels outside the app namespace must be rejected"
        );
        assert!(
            identity.derive_key("gilgamesh.kms/v1/vault-key").is_err(),
            "system labels must never be handed out"
        );
        assert!(identity.derive_key("gilgamesh.kms/v1/mac-key").is_err());
        assert!(identity.derive_key("other.namespace/v1/app/key").is_err());
        assert!(identity.derive_key("gilgamesh.kms/v10/app/key").is_err());
    }

    #[test]
    fn matches_nested_specification_formula() {
        let raw = "01".repeat(64);
        let identity = Identity::new(
            EntropySource::Coinflips(raw.clone()).seed().unwrap(),
            Some("passphrase"),
        )
        .unwrap();

        let seed = sha256(raw.as_bytes());
        let salt = &labeled_sha256(ARGON2_SALT_LABEL, &seed)[..16];
        let mut stretched = [0; 32];
        Argon2Params::INNER
            .derive(b"passphrase", salt, &mut stretched)
            .unwrap();
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&stretched), &seed);

        assert_eq!(identity.secrets.prk.0, <[u8; 32]>::from(prk));
    }
}
