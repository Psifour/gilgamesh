use super::*;

#[derive(Parser)]
pub(crate) struct Ls {
    #[command(flatten)]
    options: Options,
}

impl Ls {
    pub(crate) fn run(self) -> Result {
        // Record ids and types are public metadata; listing needs no unlock.
        // They come from an externally editable file, so they are sanitized
        // before touching the terminal.
        for record in self.options.load()?.records() {
            println!(
                "{}\t{}",
                sanitize(record.id()),
                sanitize(record.record_type())
            );
        }
        Ok(())
    }
}
