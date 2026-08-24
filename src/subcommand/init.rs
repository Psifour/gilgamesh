use super::*;

#[derive(Parser)]
#[command(
    group = clap::ArgGroup::new("entropy").required(true).multiple(false),
    // Clap would list the hidden raw-value flags in the group alternation.
    override_usage = "gilgamesh init [OPTIONS] \
        <--ask-coinflips|--ask-dice|--ask-mnemonic|--entropy-file <FILE>|--random>"
)]
pub(crate) struct Init {
    #[command(flatten)]
    options: Options,
    // The raw-value entropy and secret flags are hidden: argv leaks into
    // shell history and /proc/*/cmdline (warned about in `arguments`). They
    // exist for programmatic creation; interactive use goes through the
    // `--ask-*` prompts.
    #[arg(long, group = "entropy", hide = true, value_parser = options::secret)]
    coinflips: Option<Zeroizing<String>>,
    #[arg(
        long,
        group = "entropy",
        help = "Prompt for coinflips (ASCII '0'/'1', at least 128)."
    )]
    ask_coinflips: bool,
    #[arg(long, group = "entropy", hide = true, value_parser = options::secret)]
    dice: Option<Zeroizing<String>>,
    #[arg(
        long,
        group = "entropy",
        help = "Prompt for dice rolls (ASCII '1'-'6', at least 50)."
    )]
    ask_dice: bool,
    #[arg(long, group = "entropy", hide = true, value_parser = options::secret)]
    mnemonic: Option<Zeroizing<String>>,
    #[arg(
        long,
        group = "entropy",
        help = "Prompt for a BIP39 mnemonic (e.g. the backup printed by --random)."
    )]
    ask_mnemonic: bool,
    #[arg(
        long,
        group = "entropy",
        help = "Read raw entropy bytes from <FILE>, bit-exact."
    )]
    entropy_file: Option<PathBuf>,
    #[arg(
        long,
        group = "entropy",
        help = "Draw entropy from the system CSPRNG and print a 24-word mnemonic backup."
    )]
    random: bool,
    #[arg(long, help = "Skip the --random confirmation prompt.")]
    yes: bool,
    #[arg(
        long,
        help = "Accept a weak unlock password without interactive confirmation."
    )]
    allow_weak_password: bool,
    #[arg(
        long,
        value_name = "MIB",
        default_value_t = Argon2Params::MIN.memory_kib / 1024,
        help = "Argon2id memory cost in MiB for at-rest sealing."
    )]
    kdf_memory: u32,
    #[arg(
        long,
        default_value_t = Argon2Params::MIN.iterations,
        help = "Argon2id iteration count for at-rest sealing."
    )]
    kdf_iterations: u32,
    #[arg(
        long,
        default_value_t = Argon2Params::MIN.parallelism,
        help = "Argon2id lane count for at-rest sealing."
    )]
    kdf_parallelism: u32,
}

impl Init {
    pub(crate) fn run(self) -> Result {
        // The lock closes the check-then-store race: a concurrent init (or
        // any other mutation) can no longer clobber the vault between the
        // existence check and the rename.
        let _lock = self.options.lock()?;
        ensure!(
            !self.options.vault.exists(),
            "vault `{}` already exists",
            self.options.vault.display()
        );

        let argon2_params = Argon2Params {
            memory_kib: self
                .kdf_memory
                .checked_mul(1024)
                .context("--kdf-memory is too large")?,
            iterations: self.kdf_iterations,
            parallelism: self.kdf_parallelism,
        };
        argon2_params.validate()?;

        let mut backup_mnemonic = None;
        let source = if self.random {
            if !self.yes {
                ensure!(
                    options::stdin_is_interactive(),
                    "refusing --random non-interactively; pass --yes to accept CSPRNG entropy"
                );
                eprintln!(
                    "--random trusts the operating system's CSPRNG: unlike coinflips or dice, \
                     you cannot audit or reproduce this entropy yourself. A 24-word mnemonic \
                     backup will be printed once; it is the ONLY backup of this identity."
                );
                ensure!(
                    options::confirm("continue with CSPRNG entropy?", true)?,
                    "aborted"
                );
            }
            let (source, words) = EntropySource::generate()?;
            backup_mnemonic = Some(words);
            source
        } else if let Some(flips) = &self.coinflips {
            EntropySource::Coinflips(String::clone(flips))
        } else if self.ask_coinflips {
            EntropySource::Coinflips(rpassword::prompt_password("coinflips: ")?)
        } else if let Some(rolls) = &self.dice {
            EntropySource::Dice(String::clone(rolls))
        } else if self.ask_dice {
            EntropySource::Dice(rpassword::prompt_password("dice rolls: ")?)
        } else if let Some(words) = &self.mnemonic {
            EntropySource::Mnemonic(String::clone(words))
        } else if self.ask_mnemonic {
            EntropySource::Mnemonic(rpassword::prompt_password("mnemonic: ")?)
        } else if let Some(path) = &self.entropy_file {
            EntropySource::File(
                fs::read(path)
                    .with_context(|| format!("failed to read entropy file `{}`", path.display()))?,
            )
        } else {
            unreachable!("clap group guarantees exactly one entropy source");
        };

        let password = match &self.options.password {
            Some(password) => password.clone(),
            None => options::prompt_confirmed("unlock password")?,
        };
        options::approve_new_password(&password, self.allow_weak_password)?;

        let passphrase = self.options.new_passphrase()?;
        let (vault, identity) = Vault::create(
            source.seed()?,
            passphrase.as_deref().map(String::as_str),
            &password,
            argon2_params,
        )?;

        self.options.store(&vault)?;

        println!("vault: {}", self.options.vault.display());
        println!("fingerprint: {}", identity.fingerprint());
        if let Some(words) = &backup_mnemonic {
            println!("mnemonic: {}", **words);
            eprintln!(
                "Write down the 24-word mnemonic (and derivation passphrase, if any); it is \
                 the ONLY backup of this identity. Verify it by restoring with \
                 `gilgamesh init --ask-mnemonic` and comparing fingerprints."
            );
        } else {
            eprintln!(
                "Back up the raw entropy input (and derivation passphrase, if any); \
                 verify the fingerprint matches on restore before trusting a backup."
            );
        }

        Ok(())
    }
}
