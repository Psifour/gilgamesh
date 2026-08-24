use super::*;

#[derive(Parser)]
pub(crate) struct Fingerprint {
    #[command(flatten)]
    options: Options,
}

impl Fingerprint {
    pub(crate) fn run(self) -> Result {
        let (_, identity) = self.options.unlock()?;
        println!("{}", identity.fingerprint());
        Ok(())
    }
}
