use super::*;

const RECORDS_TAG_LABEL: &str = "gilgamesh.kms/v1/records-tag";

/// The persisted vault: everything in it is ciphertext or public. Derived
/// secrets are recomputable from identity; imported secrets exist only here,
/// so back up the file (it is safe anywhere).
#[derive(Debug, Deserialize, Serialize)]
pub struct Vault {
    version: String,
    argon2_params: Argon2Params,
    #[serde(with = "b64")]
    kek_salt: Vec<u8>,
    #[serde(default, with = "b64_opt", skip_serializing_if = "Option::is_none")]
    tpm_blob: Option<Vec<u8>>,
    #[serde(with = "b64")]
    sealed_seed: Vec<u8>,
    #[serde(with = "b64")]
    header_tag: Vec<u8>,
    records: Vec<Record>,
    /// HMAC over the record set, refreshed on every `put`/`rm`. Warn-only on
    /// mismatch: external mutation of the record set is allowed, so this
    /// detects deletion/rollback without forbidding it. Scope: it catches
    /// edits of the record set relative to the stored tag; replacing the
    /// whole file with an older, internally consistent version passes
    /// verification. Detecting that requires an anchor outside the file
    /// (e.g. a TPM NV monotonic counter, or the user noting the tag out of
    /// band).
    #[serde(default, with = "b64", skip_serializing_if = "Vec::is_empty")]
    records_tag: Vec<u8>,
}

/// Outcome of checking the record set against `records_tag`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordsIntegrity {
    /// The tag matches the current record set.
    Verified,
    /// No tag is present (older vault, or external tooling stripped it);
    /// deletion and rollback cannot be detected.
    Missing,
    /// The tag does not match: records were added, removed, reordered, or
    /// rolled back outside gilgamesh.
    Failed,
}

/// A per-record XChaCha20-Poly1305 envelope under `vault_key`, authenticated
/// against its own id and type.
#[derive(Debug, Deserialize, Serialize)]
pub struct Record {
    id: String,
    record_type: String,
    #[serde(with = "b64")]
    bytes: Vec<u8>,
}

impl Record {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn record_type(&self) -> &str {
        &self.record_type
    }

    fn ad(&self) -> String {
        format!("{}/{}", self.id, self.record_type)
    }

    fn decrypt(&self, identity: &Identity) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(self.bytes.len() > seal::NONCE_LEN, "record is truncated");
        let (nonce, ciphertext) = self.bytes.split_at(seal::NONCE_LEN);

        XChaCha20Poly1305::new(Key::from_slice(&*identity.vault_key()))
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: self.ad().as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| anyhow!("record `{}` failed authentication", sanitize(&self.id)))
    }
}

impl Vault {
    /// Seal `seed` under `unlock_password` and return the vault together with
    /// the unlocked [`Identity`]. The `derivation_passphrase` is part of the
    /// identity if used: it is immutable and never stored.
    pub fn create(
        seed: Seed,
        derivation_passphrase: Option<&str>,
        unlock_password: &str,
        argon2_params: Argon2Params,
    ) -> Result<(Self, Identity)> {
        argon2_params.validate()?;

        let kek_salt = random::<{ seal::KEK_SALT_LEN }>()?;
        let sealed_seed = seal::seal(&seed, unlock_password, &argon2_params, &kek_salt, None)?;
        let identity = Identity::new(seed, derivation_passphrase)?;

        let mut vault = Self {
            version: NAMESPACE.into(),
            argon2_params,
            kek_salt: kek_salt.to_vec(),
            tpm_blob: None,
            sealed_seed,
            header_tag: Vec::new(),
            records: Vec::new(),
            records_tag: Vec::new(),
        };
        vault.header_tag = vault.header_mac(&identity).finalize().into_bytes().to_vec();
        vault.update_records_tag(&identity);

        Ok((vault, identity))
    }

    /// Unseal the seed and re-derive the identity. Minimum argon2 params are
    /// enforced before derivation and the header tag is verified after it,
    /// which defeats parameter downgrade. A hardware-bound vault requires the
    /// sealer; a software-only vault ignores it.
    pub fn unlock(
        &self,
        unlock_password: &str,
        derivation_passphrase: Option<&str>,
        hardware: Option<&dyn HardwareSealer>,
    ) -> Result<Identity> {
        self.check_version()?;
        self.argon2_params.validate()?;

        let hardware_secret = self.hardware_secret(hardware)?;
        let seed = seal::unseal(
            &self.sealed_seed,
            unlock_password,
            &self.argon2_params,
            &self.kek_salt()?,
            hardware_secret.as_deref(),
        )?;
        let identity = Identity::new(seed, derivation_passphrase)?;

        self.header_mac(&identity)
            .verify_slice(&self.header_tag)
            .map_err(|_| {
                anyhow!(
                    "vault header failed integrity check \
                     (wrong derivation passphrase, or a corrupted/tampered vault)"
                )
            })?;

        // Warn-only by design: the record set may legitimately be mutated
        // outside gilgamesh, but silent deletion/rollback must not pass
        // unremarked.
        match self.verify_records(&identity) {
            RecordsIntegrity::Verified => {}
            RecordsIntegrity::Missing => eprintln!(
                "warning: vault has no records integrity tag (older vault or external edit); \
                 record deletion or rollback cannot be detected. The tag is refreshed by the \
                 next `put` or `rm`."
            ),
            RecordsIntegrity::Failed => eprintln!(
                "warning: RECORDS INTEGRITY CHECK FAILED: records were added, removed, \
                 reordered, or rolled back outside gilgamesh. If this was not you, treat the \
                 vault file's history as suspect."
            ),
        }

        Ok(identity)
    }

    /// Check the record set against `records_tag`. Exposed so callers can act
    /// on integrity state directly; [`Self::unlock`] warns on stderr instead
    /// of failing.
    pub fn verify_records(&self, identity: &Identity) -> RecordsIntegrity {
        if self.records_tag.is_empty() {
            return RecordsIntegrity::Missing;
        }
        match self.records_mac(identity).verify_slice(&self.records_tag) {
            Ok(()) => RecordsIntegrity::Verified,
            Err(_) => RecordsIntegrity::Failed,
        }
    }

    /// Re-seal the seed under a new unlock password. Nothing downstream
    /// rotates; a `derivation_passphrase` change is a migration instead.
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        hardware: Option<&dyn HardwareSealer>,
    ) -> Result {
        self.check_version()?;
        self.argon2_params.validate()?;

        let hardware_secret = self.hardware_secret(hardware)?;
        let seed = seal::unseal(
            &self.sealed_seed,
            old_password,
            &self.argon2_params,
            &self.kek_salt()?,
            hardware_secret.as_deref(),
        )?;

        let kek_salt = random::<{ seal::KEK_SALT_LEN }>()?;
        self.sealed_seed = seal::seal(
            &seed,
            new_password,
            &self.argon2_params,
            &kek_salt,
            hardware_secret.as_deref(),
        )?;
        self.kek_salt = kek_salt.to_vec();

        Ok(())
    }

    /// Re-seal the seed under `new_password` and `argon2_params`. Unlike
    /// [`Self::change_password`], this can change the outer KDF parameters —
    /// which re-binds the header tag, so it needs the unlocked [`Identity`].
    /// The identity must be this vault's own: it is verified against the
    /// current header tag before anything is rewritten, because a foreign
    /// identity would bind the header to keys this vault cannot derive.
    pub fn reseal(
        &mut self,
        identity: &Identity,
        new_password: &str,
        argon2_params: Argon2Params,
        hardware: Option<&dyn HardwareSealer>,
    ) -> Result {
        self.verify_identity(identity)?;
        argon2_params.validate()?;

        let hardware_secret = self.hardware_secret(hardware)?;
        let kek_salt = random::<{ seal::KEK_SALT_LEN }>()?;
        self.sealed_seed = seal::seal(
            identity.seed(),
            new_password,
            &argon2_params,
            &kek_salt,
            hardware_secret.as_deref(),
        )?;
        self.kek_salt = kek_salt.to_vec();
        self.argon2_params = argon2_params;
        self.header_tag = self.header_mac(identity).finalize().into_bytes().to_vec();

        Ok(())
    }

    /// Verify that `identity` is this vault's own by checking it against the
    /// header tag. Callers that pair a freshly loaded vault with a long-held
    /// identity (the agent) use this to refuse a swapped vault file: writing
    /// records or tags under a foreign identity's keys would corrupt them
    /// for the real owner.
    pub fn verify_identity(&self, identity: &Identity) -> Result {
        self.check_version()?;
        self.header_mac(identity)
            .verify_slice(&self.header_tag)
            .map_err(|_| anyhow!("identity does not match this vault"))
    }

    pub fn argon2_params(&self) -> Argon2Params {
        self.argon2_params
    }

    /// Refuse a vault from a different format version. Serde ignores unknown
    /// fields, so rewriting a future-versioned vault would silently strip
    /// them; every load-for-mutation path must check this, not just
    /// [`Self::unlock`].
    pub fn check_version(&self) -> Result {
        ensure!(
            self.version == NAMESPACE,
            "unsupported vault version `{}`",
            self.version
        );
        Ok(())
    }

    pub fn is_hardware_bound(&self) -> bool {
        self.tpm_blob.is_some()
    }

    /// Bind the working copy of the seed to `sealer`. Refused until the caller
    /// attests the seed backup is fingerprint-verified, because a lost or
    /// reset hardware device makes this vault file permanently undecryptable:
    /// the backup becomes the only recovery path.
    pub fn enable_hardware_binding(
        &mut self,
        unlock_password: &str,
        sealer: &dyn HardwareSealer,
        backup_verified: bool,
    ) -> Result {
        ensure!(
            backup_verified,
            "refusing to enable hardware binding until the seed backup is fingerprint-verified"
        );
        ensure!(!self.is_hardware_bound(), "vault is already hardware-bound");
        self.check_version()?;
        self.argon2_params.validate()?;

        let seed = seal::unseal(
            &self.sealed_seed,
            unlock_password,
            &self.argon2_params,
            &self.kek_salt()?,
            None,
        )?;

        let secret = Zeroizing::new(random::<32>()?);
        let blob = sealer.seal(&secret)?;

        let kek_salt = random::<{ seal::KEK_SALT_LEN }>()?;
        self.sealed_seed = seal::seal(
            &seed,
            unlock_password,
            &self.argon2_params,
            &kek_salt,
            Some(&secret),
        )?;
        self.kek_salt = kek_salt.to_vec();
        self.tpm_blob = Some(blob);

        Ok(())
    }

    /// Remove hardware binding, re-sealing software-only. This is the portable
    /// export: the resulting vault file unlocks anywhere with the password.
    pub fn disable_hardware_binding(
        &mut self,
        unlock_password: &str,
        sealer: &dyn HardwareSealer,
    ) -> Result {
        ensure!(self.is_hardware_bound(), "vault is not hardware-bound");
        self.check_version()?;
        self.argon2_params.validate()?;

        let hardware_secret = self.hardware_secret(Some(sealer))?;
        let seed = seal::unseal(
            &self.sealed_seed,
            unlock_password,
            &self.argon2_params,
            &self.kek_salt()?,
            hardware_secret.as_deref(),
        )?;

        let kek_salt = random::<{ seal::KEK_SALT_LEN }>()?;
        self.sealed_seed =
            seal::seal(&seed, unlock_password, &self.argon2_params, &kek_salt, None)?;
        self.kek_salt = kek_salt.to_vec();
        self.tpm_blob = None;

        Ok(())
    }

    fn hardware_secret(
        &self,
        hardware: Option<&dyn HardwareSealer>,
    ) -> Result<Option<Zeroizing<[u8; 32]>>> {
        match (&self.tpm_blob, hardware) {
            (None, _) => Ok(None),
            (Some(blob), Some(sealer)) => Ok(Some(sealer.unseal(blob)?)),
            (Some(_), None) => Err(anyhow!(
                "vault is hardware-bound; unlocking requires the bound hardware"
            )),
        }
    }

    /// Read and parse the vault at `path`, refusing a foreign format
    /// version. The counterpart of [`Self::store`]; external tools should use
    /// these instead of raw file IO to inherit the version check and the
    /// atomic-write discipline.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let vault = Self::from_bytes(
            &fs::read(path)
                .with_context(|| format!("failed to read vault `{}`", path.display()))?,
        )?;
        // Checked at load so every path — including mutations that never
        // unlock — refuses a foreign format version instead of silently
        // rewriting it.
        vault.check_version()?;
        Ok(vault)
    }

    /// Atomic and durable: write a 0600 temp file, fsync it, rename over the
    /// vault, fsync the directory. Without the syncs a crash can replace the
    /// vault — the only home of imported records — with a truncated file.
    pub fn store(&self, path: &std::path::Path) -> Result {
        let tmp = path.with_extension("vault.tmp");

        {
            let mut open = fs::OpenOptions::new();
            open.write(true).create(true).truncate(true);
            // On Windows no explicit DACL is applied: the file inherits the
            // parent directory's ACLs, which in a user-profile directory
            // restrict access to the user. The vault is ciphertext-or-public
            // either way.
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);

            let mut file = open
                .open(&tmp)
                .with_context(|| format!("failed to write vault `{}`", tmp.display()))?;
            file.write_all(&self.to_bytes()?)
                .with_context(|| format!("failed to write vault `{}`", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync vault `{}`", tmp.display()))?;
        }

        fs::rename(&tmp, path)
            .with_context(|| format!("failed to replace vault `{}`", path.display()))?;

        #[cfg(unix)]
        {
            let dir = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => std::path::Path::new("."),
            };
            fs::File::open(dir)
                .and_then(|dir| dir.sync_all())
                .with_context(|| format!("failed to sync vault directory `{}`", dir.display()))?;
        }

        Ok(())
    }

    /// Advisory exclusive lock serializing vault mutations. Every
    /// load-modify-store cycle must hold it, or concurrent invocations
    /// silently lose one write (the last rename wins). Readers need no lock:
    /// [`Self::store`] replaces the vault atomically. The lock lives on a
    /// stable sibling path because locking the vault file itself would be
    /// defeated by the rename; the lock file is left in place, since
    /// unlinking it would reopen the race.
    pub fn lock_file(path: &std::path::Path) -> Result<fs::File> {
        let path = path.with_extension("vault.lock");

        let mut open = fs::OpenOptions::new();
        open.write(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);

        let file = open
            .open(&path)
            .with_context(|| format!("failed to open lock file `{}`", path.display()))?;
        file.lock()
            .with_context(|| format!("failed to lock `{}`", path.display()))?;

        Ok(file)
    }

    /// Encrypt `plaintext` as a record, replacing any record with the same id.
    pub fn put(
        &mut self,
        identity: &Identity,
        id: &str,
        record_type: &str,
        plaintext: &[u8],
    ) -> Result {
        ensure!(
            !id.is_empty() && !id.contains('/'),
            "record id must be non-empty and must not contain '/'"
        );
        ensure!(
            !record_type.is_empty() && !record_type.contains('/'),
            "record type must be non-empty and must not contain '/'"
        );

        let mut record = Record {
            id: id.into(),
            record_type: record_type.into(),
            bytes: Vec::new(),
        };

        let nonce = random::<{ seal::NONCE_LEN }>()?;
        let mut ciphertext = XChaCha20Poly1305::new(Key::from_slice(&*identity.vault_key()))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: record.ad().as_bytes(),
                },
            )
            .map_err(|_| anyhow!("failed to encrypt record `{id}`"))?;

        record.bytes = nonce.to_vec();
        record.bytes.append(&mut ciphertext);

        self.records.retain(|record| record.id != id);
        self.records.push(record);
        self.update_records_tag(identity);

        Ok(())
    }

    pub fn get(&self, identity: &Identity, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.records
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| anyhow!("no record with id `{id}`"))?
            .decrypt(identity)
    }

    /// Remove a record. Takes the identity so `records_tag` stays in step;
    /// a removal is a legitimate mutation, not a rollback.
    pub fn remove(&mut self, identity: &Identity, id: &str) -> bool {
        let len = self.records.len();
        self.records.retain(|record| record.id != id);
        let removed = self.records.len() != len;
        if removed {
            self.update_records_tag(identity);
        }
        removed
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// MAC over the version and KDF parameters. Domain separation from
    /// `records_mac` (both run under `mac_key`) is implicit: after the shared
    /// version prefix this input continues with "/m=" (canonical params
    /// always start "m="), while the records input continues with
    /// "/records-tag". Those prefixes must stay distinct if either format
    /// ever changes.
    fn header_mac(&self, identity: &Identity) -> HmacSha256 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&*identity.mac_key())
            .expect("HMAC-SHA256 accepts 32-byte keys");
        mac.update(format!("{}/{}", self.version, self.argon2_params.canonical()).as_bytes());
        mac
    }

    /// MAC over the full record set: a label to domain-separate from
    /// `header_mac` (both run under `mac_key`), then every field of every
    /// record, length-prefixed for unambiguous framing.
    fn records_mac(&self, identity: &Identity) -> HmacSha256 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&*identity.mac_key())
            .expect("HMAC-SHA256 accepts 32-byte keys");
        mac.update(RECORDS_TAG_LABEL.as_bytes());
        for record in &self.records {
            for field in [
                record.id.as_bytes(),
                record.record_type.as_bytes(),
                record.bytes.as_slice(),
            ] {
                mac.update(&(field.len() as u64).to_le_bytes());
                mac.update(field);
            }
        }
        mac
    }

    fn update_records_tag(&mut self, identity: &Identity) {
        self.records_tag = self.records_mac(identity).finalize().into_bytes().to_vec();
    }

    fn kek_salt(&self) -> Result<[u8; seal::KEK_SALT_LEN]> {
        self.kek_salt
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("vault kek salt has invalid length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> (Vault, Identity) {
        Vault::create(
            Seed::from_bytes([0x42; 32]),
            None,
            "hunter22",
            Argon2Params::default(),
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_through_bytes() {
        let (mut vault, identity) = test_vault();
        vault
            .put(
                &identity,
                "peer-alice",
                "x25519-public-key",
                b"alice public key",
            )
            .unwrap();

        let restored = Vault::from_bytes(&vault.to_bytes().unwrap()).unwrap();
        let unlocked = restored.unlock("hunter22", None, None).unwrap();

        assert_eq!(unlocked.fingerprint(), identity.fingerprint());
        assert_eq!(
            *restored.get(&unlocked, "peer-alice").unwrap(),
            b"alice public key"
        );
        assert!(restored.unlock("hunter23", None, None).is_err());
    }

    #[test]
    fn records_replace_and_remove() {
        let (mut vault, identity) = test_vault();

        vault.put(&identity, "note", "password", b"first").unwrap();
        vault.put(&identity, "note", "password", b"second").unwrap();
        assert_eq!(vault.records().len(), 1);
        assert_eq!(*vault.get(&identity, "note").unwrap(), b"second");

        assert!(vault.remove(&identity, "note"));
        assert!(!vault.remove(&identity, "note"));
        assert!(vault.get(&identity, "note").is_err());
        assert!(
            vault
                .put(&identity, "with/slash", "password", b"x")
                .is_err()
        );
    }

    #[test]
    fn records_tag_tracks_mutations_and_detects_external_ones() {
        let (mut vault, identity) = test_vault();
        assert_eq!(
            vault.verify_records(&identity),
            RecordsIntegrity::Verified,
            "a fresh vault must carry a valid (empty-set) records tag"
        );

        vault.put(&identity, "a", "secret", b"one").unwrap();
        vault.put(&identity, "b", "secret", b"two").unwrap();
        assert!(vault.remove(&identity, "b"));
        assert_eq!(vault.verify_records(&identity), RecordsIntegrity::Verified);

        let mut json: serde_json::Value =
            serde_json::from_slice(&vault.to_bytes().unwrap()).unwrap();

        // External deletion: record vanishes but the tag stays behind.
        let mut deleted = json.clone();
        deleted["records"].as_array_mut().unwrap().clear();
        let deleted = Vault::from_bytes(&serde_json::to_vec(&deleted).unwrap()).unwrap();
        assert_eq!(deleted.verify_records(&identity), RecordsIntegrity::Failed);
        assert!(
            deleted.unlock("hunter22", None, None).is_ok(),
            "records integrity is warn-only; unlock must still succeed"
        );

        // Older vaults (or external tooling) have no tag at all.
        json.as_object_mut().unwrap().remove("records_tag");
        let untagged = Vault::from_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(
            untagged.verify_records(&identity),
            RecordsIntegrity::Missing
        );
        assert!(untagged.unlock("hunter22", None, None).is_ok());
    }

    #[test]
    fn parameter_downgrade_is_rejected_before_derivation() {
        let (vault, _) = test_vault();

        let mut json: serde_json::Value =
            serde_json::from_slice(&vault.to_bytes().unwrap()).unwrap();
        json["argon2_params"]["memory_kib"] = 1024.into();

        let downgraded = Vault::from_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(
            downgraded
                .unlock("hunter22", None, None)
                .unwrap_err()
                .to_string()
                .contains("below minimum")
        );
    }

    #[test]
    fn tampered_header_tag_is_rejected() {
        let (vault, _) = test_vault();

        let mut json: serde_json::Value =
            serde_json::from_slice(&vault.to_bytes().unwrap()).unwrap();
        json["header_tag"] = BASE64.encode([0; 32]).into();

        let tampered = Vault::from_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(
            tampered
                .unlock("hunter22", None, None)
                .unwrap_err()
                .to_string()
                .contains("integrity")
        );
    }

    #[test]
    fn password_change_keeps_identity_and_records() {
        let (mut vault, identity) = test_vault();
        vault.put(&identity, "note", "password", b"secret").unwrap();

        vault
            .change_password("hunter22", "correct horse", None)
            .unwrap();
        assert!(vault.unlock("hunter22", None, None).is_err());

        let unlocked = vault.unlock("correct horse", None, None).unwrap();
        assert_eq!(
            *unlocked.ssh_seed("default").unwrap(),
            *identity.ssh_seed("default").unwrap()
        );
        assert_eq!(*vault.get(&unlocked, "note").unwrap(), b"secret");
    }

    #[test]
    fn reseal_changes_kdf_params_and_rebinds_header() {
        let (mut vault, identity) = test_vault();
        vault.put(&identity, "note", "password", b"secret").unwrap();

        let params = Argon2Params {
            memory_kib: 128 * 1024,
            ..Argon2Params::MIN
        };
        vault
            .reseal(&identity, "correct horse", params, None)
            .unwrap();
        assert_eq!(vault.argon2_params(), params);

        assert!(vault.unlock("hunter22", None, None).is_err());
        let unlocked = vault.unlock("correct horse", None, None).unwrap();
        assert_eq!(
            *unlocked.ssh_seed("default").unwrap(),
            *identity.ssh_seed("default").unwrap()
        );
        assert_eq!(*vault.get(&unlocked, "note").unwrap(), b"secret");

        // A foreign identity would bind the header to underivable keys; it
        // must be rejected before anything is rewritten.
        let foreign = Identity::new(Seed::from_bytes([0x43; 32]), None).unwrap();
        assert!(
            vault
                .reseal(&foreign, "x", params, None)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
        assert!(vault.unlock("correct horse", None, None).is_ok());
    }

    #[test]
    fn reseal_on_a_hardware_bound_vault_requires_and_keeps_the_binding() {
        let (mut vault, identity) = test_vault();
        let sealer = hardware::tests::MockSealer { key: 0x5a };
        vault
            .enable_hardware_binding("hunter22", &sealer, true)
            .unwrap();

        let params = Argon2Params {
            iterations: 4,
            ..Argon2Params::MIN
        };
        assert!(
            vault
                .reseal(&identity, "correct horse", params, None)
                .is_err(),
            "a bound vault must refuse to reseal without the hardware"
        );

        vault
            .reseal(&identity, "correct horse", params, Some(&sealer))
            .unwrap();
        assert_eq!(vault.argon2_params(), params);
        assert!(vault.is_hardware_bound());

        // Both factors are still required, and the identity is unchanged.
        assert!(vault.unlock("correct horse", None, None).is_err());
        assert!(vault.unlock("hunter22", None, Some(&sealer)).is_err());
        let unlocked = vault.unlock("correct horse", None, Some(&sealer)).unwrap();
        assert_eq!(
            *unlocked.ssh_seed("default").unwrap(),
            *identity.ssh_seed("default").unwrap()
        );
    }

    #[test]
    fn hardware_binding_requires_verified_backup_and_both_factors() {
        let (mut vault, identity) = test_vault();
        let sealer = hardware::tests::MockSealer { key: 0x5a };

        assert!(
            vault
                .enable_hardware_binding("hunter22", &sealer, false)
                .unwrap_err()
                .to_string()
                .contains("fingerprint-verified")
        );
        assert!(!vault.is_hardware_bound());

        vault
            .enable_hardware_binding("hunter22", &sealer, true)
            .unwrap();
        assert!(vault.is_hardware_bound());
        assert!(
            vault
                .enable_hardware_binding("hunter22", &sealer, true)
                .is_err(),
            "double-enable must be rejected"
        );

        // Password alone, hardware alone with the wrong password, and the
        // wrong hardware must all fail; both factors together must succeed
        // with derived keys unchanged.
        assert!(vault.unlock("hunter22", None, None).is_err());
        assert!(vault.unlock("hunter23", None, Some(&sealer)).is_err());
        let wrong = hardware::tests::MockSealer { key: 0xa5 };
        assert!(vault.unlock("hunter22", None, Some(&wrong)).is_err());

        let unlocked = vault.unlock("hunter22", None, Some(&sealer)).unwrap();
        assert_eq!(
            *unlocked.ssh_seed("default").unwrap(),
            *identity.ssh_seed("default").unwrap()
        );
    }

    #[test]
    fn hardware_binding_survives_serialization_and_password_change() {
        let (mut vault, _) = test_vault();
        let sealer = hardware::tests::MockSealer { key: 0x5a };

        vault
            .enable_hardware_binding("hunter22", &sealer, true)
            .unwrap();

        let mut restored = Vault::from_bytes(&vault.to_bytes().unwrap()).unwrap();
        assert!(restored.is_hardware_bound());
        assert!(restored.unlock("hunter22", None, Some(&sealer)).is_ok());

        assert!(
            restored
                .change_password("hunter22", "correct horse", None)
                .is_err(),
            "password change on a bound vault requires the hardware"
        );
        restored
            .change_password("hunter22", "correct horse", Some(&sealer))
            .unwrap();
        assert!(
            restored
                .unlock("correct horse", None, Some(&sealer))
                .is_ok()
        );
    }

    #[test]
    fn disable_hardware_binding_is_portable_export() {
        let (mut vault, identity) = test_vault();
        let sealer = hardware::tests::MockSealer { key: 0x5a };

        assert!(
            vault.disable_hardware_binding("hunter22", &sealer).is_err(),
            "disable on an unbound vault must be rejected"
        );

        vault
            .enable_hardware_binding("hunter22", &sealer, true)
            .unwrap();
        vault.disable_hardware_binding("hunter22", &sealer).unwrap();

        assert!(!vault.is_hardware_bound());
        let unlocked = vault.unlock("hunter22", None, None).unwrap();
        assert_eq!(unlocked.fingerprint(), identity.fingerprint());
    }
}
