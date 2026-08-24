use super::*;

#[derive(Parser)]
pub(crate) struct MnemonicCommand {
    #[command(flatten)]
    options: Options,
    #[arg(default_value = "default", help = "Derive the wallet named <KEYNAME>.")]
    keyname: String,
}

impl MnemonicCommand {
    pub(crate) fn run(self) -> Result {
        let (_, identity) = self.options.unlock()?;
        println!("{}", *identity.bip39_mnemonic(&self.keyname)?);
        Ok(())
    }
}
