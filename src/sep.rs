use {
    super::*,
    core_foundation::{base::TCFType, string::CFString},
    security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        item::{ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult},
        key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    },
    security_framework_sys::{
        access_control::kSecAccessControlPrivateKeyUsage,
        item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave},
    },
};

/// Keychain label of the enclave-resident key; frozen like every namespace
/// label. Deleting the key orphans every blob sealed to it — the entropy
/// backup is then the only recovery path, by design.
pub const KEY_LABEL: &str = "gilgamesh.kms/v1/sep-key";

const BLOB_MAGIC: &[u8] = b"gilgamesh.kms/v1/sep-blob/";

const ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_MISSING_ENTITLEMENT: isize = -34018;

/// macOS Secure Enclave [`HardwareSealer`]: one persistent enclave-resident
/// P-256 key wraps hardware secrets via ECIES. Enclave keys live in the data
/// protection keychain, so the binary must be signed with an App ID
/// (keychain-access-groups); per-application isolation is enforced by the OS
/// through code signing.
pub struct SepSealer;

impl SepSealer {
    pub fn open() -> Result<Self> {
        Ok(Self)
    }

    fn find_key() -> Result<Option<SecKey>> {
        let results = match ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(KEY_LABEL)
            .ignore_legacy_keychains()
            .load_refs(true)
            .limit(Limit::All)
            .search()
        {
            Ok(results) => results,
            Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
            Err(err) => return Err(anyhow!("keychain search failed: {err}")),
        };

        let keys: Vec<SecKey> = results
            .into_iter()
            .filter_map(|result| match result {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            })
            .collect();

        if keys.is_empty() {
            return Ok(None);
        }

        // The label alone must not select the key: a software key planted (or
        // accidentally created) under it would be used for sealing while the
        // vault reports Secure Enclave binding it does not have. Fail loudly
        // instead of silently degrading.
        let enclave: Vec<SecKey> = keys.into_iter().filter(Self::is_enclave_resident).collect();
        ensure!(
            !enclave.is_empty(),
            "keychain key `{KEY_LABEL}` is not Secure Enclave-resident; refusing to use it"
        );

        // Should duplicates exist under the label (older builds could race
        // key creation), keychain search order must not pick one arbitrarily:
        // select by smallest application label (the hash of the public key)
        // so every lookup converges on the same key.
        Ok(enclave
            .into_iter()
            .min_by_key(|key| key.application_label()))
    }

    /// True when the key's `kSecAttrTokenID` marks it as enclave-resident.
    fn is_enclave_resident(key: &SecKey) -> bool {
        use core_foundation::base::ToVoid;

        key.attributes()
            .find(unsafe { kSecAttrTokenID }.to_void())
            .is_some_and(|token| {
                let token = unsafe { CFString::wrap_under_get_rule(token.cast()) };
                let enclave =
                    unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
                token.as_CFType() == enclave.as_CFType()
            })
    }

    fn get_or_create_key() -> Result<SecKey> {
        if let Some(key) = Self::find_key()? {
            return Ok(key);
        }

        // First-ever seal: serialize creation on an advisory lock and re-run
        // the search under it, or two concurrent first seals each create a
        // key and one ends up with blobs sealed to a key later lookups will
        // not pick. The lock is per-user, like the keychain itself: the uid
        // in the name keeps users from colliding on the 0600 file when
        // temp_dir falls back to a shared /tmp (e.g. SSH sessions without
        // TMPDIR).
        let lock_path = env::temp_dir().join(format!("gilgamesh.kms-v1-sep-key.{}.lock", unsafe {
            libc::getuid()
        }));
        let mut open = fs::OpenOptions::new();
        open.write(true).create(true);
        std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
        let lock = open
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file `{}`", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("failed to lock `{}`", lock_path.display()))?;

        if let Some(key) = Self::find_key()? {
            return Ok(key);
        }

        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage as usize,
        )
        .map_err(|err| anyhow!("failed to create access control: {err}"))?;

        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_label(KEY_LABEL)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access);

        SecKey::new(&options).map_err(|err| {
            if err.code() == ERR_SEC_MISSING_ENTITLEMENT {
                anyhow!(
                    "Secure Enclave requires the data protection keychain: this binary must \
                     be code-signed with an App ID and keychain-access-groups entitlement \
                     (errSecMissingEntitlement)"
                )
            } else {
                anyhow!("Secure Enclave key generation failed: {err}")
            }
        })
    }
}

impl HardwareSealer for SepSealer {
    fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let key = Self::get_or_create_key()?;
        let public = key
            .public_key()
            .ok_or_else(|| anyhow!("Secure Enclave key has no public half"))?;

        let ciphertext = public
            .encrypt_data(ALGORITHM, secret)
            .map_err(|err| anyhow!("Secure Enclave seal failed: {err}"))?;

        let mut blob = BLOB_MAGIC.to_vec();
        blob.extend_from_slice(&ciphertext);

        Ok(blob)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let body = blob
            .strip_prefix(BLOB_MAGIC)
            .ok_or_else(|| anyhow!("not a gilgamesh Secure Enclave blob"))?;

        let key = Self::find_key()?
            .ok_or_else(|| anyhow!("Secure Enclave key `{KEY_LABEL}` not found in keychain"))?;

        let mut plaintext = key
            .decrypt_data(ALGORITHM, body)
            .map_err(|_| anyhow!("Secure Enclave refused to unseal this blob"))?;

        let secret = plaintext
            .as_slice()
            .try_into()
            .map(|bytes: [u8; 32]| Zeroizing::new(bytes))
            .map_err(|_| anyhow!("Secure Enclave blob has invalid length"));
        plaintext.zeroize();

        secret
    }

    fn describe(&self) -> String {
        "Secure Enclave".into()
    }
}
