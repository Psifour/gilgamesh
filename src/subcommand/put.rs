use super::*;

#[derive(Parser)]
pub(crate) struct Put {
    #[command(flatten)]
    options: Options,
    #[arg(help = "Record <ID>.")]
    id: String,
    #[arg(default_value = "secret", help = "Record <TYPE>.")]
    record_type: String,
}

impl Put {
    pub(crate) fn run(self) -> Result {
        let mut plaintext = Zeroizing::new(Vec::new());
        io::stdin()
            .read_to_end(&mut plaintext)
            .context("failed to read record plaintext from stdin")?;

        let _lock = self.options.lock()?;
        let (mut vault, identity) = self.options.unlock()?;
        vault.put(&identity, &self.id, &self.record_type, &plaintext)?;
        self.options.store(&vault)?;

        Ok(())
    }
}
