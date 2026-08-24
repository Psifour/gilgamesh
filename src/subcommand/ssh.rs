use super::*;

#[derive(Parser)]
pub(crate) struct Ssh {
    #[command(flatten)]
    options: Options,
    #[arg(default_value = "default", help = "Derive the key named <KEYNAME>.")]
    keyname: String,
    #[arg(
        long,
        help = "Print the private key in OpenSSH format instead of the public key. \
                Never encrypted; pipe to ssh-agent or an ephemeral file."
    )]
    private: bool,
}

impl Ssh {
    pub(crate) fn run(self) -> Result {
        let (_, identity) = self.options.unlock()?;

        let keypair = Ed25519Keypair::from_seed(&*identity.ssh_seed(&self.keyname)?);
        let key = PrivateKey::new(
            KeypairData::Ed25519(keypair),
            format!("gilgamesh:{}", self.keyname),
        )?;

        if self.private {
            print!("{}", key.to_openssh(LineEnding::LF)?.as_str());
        } else {
            println!("{}", key.public_key().to_openssh()?);
        }

        Ok(())
    }
}
