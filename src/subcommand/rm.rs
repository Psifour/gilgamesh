use super::*;

#[derive(Parser)]
pub(crate) struct Rm {
    #[command(flatten)]
    options: Options,
    #[arg(help = "Record <ID>.")]
    id: String,
}

impl Rm {
    pub(crate) fn run(self) -> Result {
        // Unlocks (unlike `ls`) so the records integrity tag can be refreshed:
        // an authenticated removal is a mutation, not a rollback.
        let _lock = self.options.lock()?;
        let (mut vault, identity) = self.options.unlock()?;
        ensure!(
            vault.remove(&identity, &self.id),
            "no record with id `{}`",
            self.id
        );
        self.options.store(&vault)?;
        Ok(())
    }
}
