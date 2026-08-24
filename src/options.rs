use super::*;

/// Parse a secret-valued argument into zeroizing memory. The argv/environ
/// copies the OS holds are beyond reach (and warned about in `arguments`),
/// but the parsed copy must not linger unwiped in the heap.
pub(crate) fn secret(value: &str) -> Result<Zeroizing<String>, std::convert::Infallible> {
    Ok(Zeroizing::new(value.into()))
}

/// No `Debug`: holds the unlock password and derivation passphrase.
#[derive(Args)]
pub(crate) struct Options {
    #[arg(
        long,
        env = "GILGAMESH_VAULT",
        default_value = "gilgamesh.vault",
        help = "Vault file <PATH>."
    )]
    pub(crate) vault: PathBuf,
    // Hidden: passing secrets on the command line leaks them into shell
    // history and /proc/*/cmdline (warned about in `arguments`); the flag
    // exists for programmatic use. Interactive use prompts, scripts should
    // prefer the environment variable.
    #[arg(
        long,
        env = "GILGAMESH_PASSWORD",
        hide = true,
        hide_env_values = true,
        value_parser = secret
    )]
    pub(crate) password: Option<Zeroizing<String>>,
    #[arg(
        long,
        env = "GILGAMESH_PASSPHRASE",
        hide = true,
        hide_env_values = true,
        value_parser = secret
    )]
    pub(crate) passphrase: Option<Zeroizing<String>>,
    #[arg(
        long,
        conflicts_with = "passphrase",
        help = "Prompt for the derivation passphrase (immutable part of the identity)."
    )]
    pub(crate) ask_passphrase: bool,
}

impl Options {
    pub(crate) fn password(&self) -> Result<Zeroizing<String>> {
        Ok(match &self.password {
            Some(password) => password.clone(),
            None => Zeroizing::new(rpassword::prompt_password("unlock password: ")?),
        })
    }

    pub(crate) fn passphrase(&self) -> Result<Option<Zeroizing<String>>> {
        let passphrase = match &self.passphrase {
            Some(passphrase) => Some(passphrase.clone()),
            None if self.ask_passphrase => Some(Zeroizing::new(rpassword::prompt_password(
                "derivation passphrase: ",
            )?)),
            None => None,
        };

        Ok(passphrase.filter(|passphrase| !passphrase.is_empty()))
    }

    /// Like [`Self::passphrase`], but for identity creation: a prompted
    /// passphrase is confirmed by double entry. A typo here would create a
    /// permanently different identity that backup verification cannot catch,
    /// because the fingerprint covers the seed only.
    pub(crate) fn new_passphrase(&self) -> Result<Option<Zeroizing<String>>> {
        let passphrase = match &self.passphrase {
            Some(passphrase) => Some(passphrase.clone()),
            None if self.ask_passphrase => Some(prompt_confirmed("derivation passphrase")?),
            None => None,
        };

        Ok(passphrase.filter(|passphrase| !passphrase.is_empty()))
    }

    pub(crate) fn lock(&self) -> Result<fs::File> {
        Vault::lock_file(&self.vault)
    }

    pub(crate) fn load(&self) -> Result<Vault> {
        Vault::load(&self.vault)
    }

    pub(crate) fn store(&self, vault: &Vault) -> Result {
        vault.store(&self.vault)
    }

    pub(crate) fn unlock(&self) -> Result<(Vault, Identity)> {
        let vault = self.load()?;
        let hardware = hardware_sealer(&vault)?;
        let password = self.password()?;
        let passphrase = self.passphrase()?;
        let identity = vault.unlock(
            &password,
            passphrase.as_deref().map(String::as_str),
            hardware.as_deref(),
        )?;
        Ok((vault, identity))
    }
}

/// The sealer for a vault's current binding state: `None` for software-only
/// vaults, the platform backend for hardware-bound ones.
pub(crate) fn hardware_sealer(vault: &Vault) -> Result<Option<Box<dyn HardwareSealer>>> {
    if vault.is_hardware_bound() {
        Ok(Some(open_sealer()?))
    } else {
        Ok(None)
    }
}

pub(crate) fn open_sealer() -> Result<Box<dyn HardwareSealer>> {
    hardware::platform_sealer()
}

pub(crate) fn prompt_confirmed(label: &str) -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password(format!("{label}: "))?);
    let second = Zeroizing::new(rpassword::prompt_password(format!("confirm {label}: "))?);
    ensure!(*first == *second, "{label} entries do not match");
    Ok(first)
}

pub(crate) fn stdin_is_interactive() -> bool {
    io::stdin().is_terminal()
}

pub(crate) fn confirm(prompt: &str, default_yes: bool) -> Result<bool> {
    eprint!("{prompt} {} ", if default_yes { "[Y/n]" } else { "[y/N]" });
    io::stderr().flush()?;

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;

    Ok(match line.trim().to_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    })
}

/// Crude upper-bound estimate: length × log2 of the union of character
/// classes present. Overestimates structured ASCII passwords (it cannot see
/// words), so it under-warns there. Non-ASCII characters are lumped into the
/// 33-symbol class, so a password drawing on a large non-Latin alphabet may
/// be underestimated and draw a spurious warning — which the user can
/// override, per the policy below.
pub(crate) fn estimate_password_bits(password: &str) -> f64 {
    let mut classes = [false; 4];
    for c in password.chars() {
        let class = if c.is_ascii_lowercase() {
            0
        } else if c.is_ascii_uppercase() {
            1
        } else if c.is_ascii_digit() {
            2
        } else {
            3
        };
        classes[class] = true;
    }

    let alphabet: u32 = [26u32, 26, 10, 33]
        .iter()
        .zip(classes)
        .filter(|(_, present)| *present)
        .map(|(size, _)| size)
        .sum();

    password.chars().count() as f64 * f64::from(alphabet.max(1)).log2()
}

/// The design floor: five diceware words, ~64 bits raw.
const WEAK_PASSWORD_BITS: f64 = 64.0;

/// Warn about a weak unlock password and require explicit approval. The user
/// keeps the final say: interactively via y/N, programmatically via
/// `--allow-weak-password`; only a weak password with neither is refused.
pub(crate) fn approve_new_password(password: &str, allow_weak: bool) -> Result {
    let bits = estimate_password_bits(password);
    if bits >= WEAK_PASSWORD_BITS {
        return Ok(());
    }

    eprintln!(
        "warning: this unlock password is weak (at most ~{bits:.0} bits; the floor is five \
         diceware words, ~64 bits). At-rest protection is password entropy plus ~22 bits of \
         Argon2 hardness; below ~40 bits it is theater."
    );

    if allow_weak {
        return Ok(());
    }
    ensure!(
        stdin_is_interactive(),
        "refusing a weak unlock password non-interactively; choose a stronger one or pass \
         --allow-weak-password"
    );
    ensure!(
        confirm("use this weak password anyway?", false)?,
        "aborted: weak unlock password rejected"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_strength_estimate_is_an_upper_bound() {
        assert_eq!(estimate_password_bits(""), 0.0);
        assert!(estimate_password_bits("hunter22") < WEAK_PASSWORD_BITS);
        assert!(estimate_password_bits("correct horse battery staple") >= WEAK_PASSWORD_BITS);
        assert!(estimate_password_bits("Tr0ub4dor&3xyz") >= WEAK_PASSWORD_BITS);
    }
}
