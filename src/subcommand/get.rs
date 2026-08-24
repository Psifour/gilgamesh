use super::*;

#[derive(Parser)]
pub(crate) struct Get {
    #[command(flatten)]
    options: Options,
    #[arg(help = "Record <ID>.")]
    id: String,
}

impl Get {
    pub(crate) fn run(self) -> Result {
        let (vault, identity) = self.options.unlock()?;
        io::stdout().write_all(&vault.get(&identity, &self.id)?)?;
        Ok(())
    }
}
