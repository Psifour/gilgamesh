use super::*;

#[derive(Parser)]
pub(crate) struct ChangePassword {
    #[command(flatten)]
    options: Options,
    // Hidden like every secret-valued flag; see `arguments`. Prefer the
    // environment variable or the interactive prompt.
    #[arg(
        long,
        env = "GILGAMESH_NEW_PASSWORD",
        hide = true,
        hide_env_values = true,
        value_parser = options::secret
    )]
    new_password: Option<Zeroizing<String>>,
    #[arg(
        long,
        help = "Accept a weak unlock password without interactive confirmation."
    )]
    allow_weak_password: bool,
    // KDF parameters only apply to at-rest sealing, so changing them is a
    // re-seal like a password change — but they are bound by the header tag,
    // which needs the unlocked identity to recompute (and therefore the
    // derivation passphrase, if the identity uses one).
    #[arg(
        long,
        value_name = "MIB",
        help = "Change the Argon2id memory cost to <MIB> MiB (needs the derivation \
                passphrase, if set)."
    )]
    kdf_memory: Option<u32>,
    #[arg(
        long,
        help = "Change the Argon2id iteration count (needs the derivation passphrase, if set)."
    )]
    kdf_iterations: Option<u32>,
    #[arg(
        long,
        help = "Change the Argon2id lane count (needs the derivation passphrase, if set)."
    )]
    kdf_parallelism: Option<u32>,
}

impl ChangePassword {
    pub(crate) fn run(self) -> Result {
        let _lock = self.options.lock()?;

        if self.kdf_memory.is_some()
            || self.kdf_iterations.is_some()
            || self.kdf_parallelism.is_some()
        {
            // Full unlock: it verifies the old password, the header tag, and
            // the derivation passphrase before the new password is prompted
            // for or anything is rewritten.
            let (mut vault, identity) = self.options.unlock()?;

            let current = vault.argon2_params();
            let argon2_params = Argon2Params {
                memory_kib: match self.kdf_memory {
                    Some(mib) => mib.checked_mul(1024).context("--kdf-memory is too large")?,
                    None => current.memory_kib,
                },
                iterations: self.kdf_iterations.unwrap_or(current.iterations),
                parallelism: self.kdf_parallelism.unwrap_or(current.parallelism),
            };

            let new_password = self.new_password()?;
            options::approve_new_password(&new_password, self.allow_weak_password)?;

            let hardware = options::hardware_sealer(&vault)?;
            vault.reseal(&identity, &new_password, argon2_params, hardware.as_deref())?;
            self.options.store(&vault)?;
        } else {
            let mut vault = self.options.load()?;
            let hardware = options::hardware_sealer(&vault)?;

            // Old password first (natural entry order), then the new one. The
            // strength check still runs before the old password is verified: a
            // real verify-first flow would need an extra unseal.
            let old_password = self.options.password()?;
            let new_password = self.new_password()?;
            options::approve_new_password(&new_password, self.allow_weak_password)?;

            vault.change_password(&old_password, &new_password, hardware.as_deref())?;
            self.options.store(&vault)?;
        }

        Ok(())
    }

    fn new_password(&self) -> Result<Zeroizing<String>> {
        Ok(match &self.new_password {
            Some(password) => password.clone(),
            None => options::prompt_confirmed("new unlock password")?,
        })
    }
}
