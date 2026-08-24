use super::*;

#[derive(Parser)]
pub(crate) struct Hardware {
    #[command(subcommand)]
    command: HardwareCommand,
}

#[derive(Parser)]
enum HardwareCommand {
    #[command(about = "Show binding state and backend availability")]
    Status(Status),
    #[command(about = "Bind the vault's working copy to this machine's hardware")]
    Enable(Enable),
    #[command(about = "Remove hardware binding, making the vault file portable again")]
    Disable(Disable),
}

impl Hardware {
    pub(crate) fn run(self) -> Result {
        match self.command {
            HardwareCommand::Status(status) => status.run(),
            HardwareCommand::Enable(enable) => enable.run(),
            HardwareCommand::Disable(disable) => disable.run(),
        }
    }
}

#[derive(Parser)]
struct Status {
    #[command(flatten)]
    options: Options,
}

impl Status {
    fn run(self) -> Result {
        let vault = self.options.load()?;
        println!(
            "binding: {}",
            if vault.is_hardware_bound() {
                "hardware"
            } else {
                "software-only"
            }
        );

        match options::open_sealer() {
            Ok(sealer) => println!("backend: {}", sealer.describe()),
            Err(err) => println!("backend: unavailable ({err})"),
        }

        Ok(())
    }
}

#[derive(Parser)]
struct Enable {
    #[command(flatten)]
    options: Options,
    #[arg(
        long,
        help = "Attest that the seed backup has been fingerprint-verified. Once bound, \
                this vault file can only be opened on this machine; if the hardware is \
                lost or reset, the backup is the only recovery path."
    )]
    backup_verified: bool,
}

impl Enable {
    fn run(self) -> Result {
        let _lock = self.options.lock()?;
        let mut vault = self.options.load()?;
        let sealer = options::open_sealer()?;

        vault.enable_hardware_binding(&self.options.password()?, &*sealer, self.backup_verified)?;
        self.options.store(&vault)?;

        println!("bound to: {}", sealer.describe());
        Ok(())
    }
}

#[derive(Parser)]
struct Disable {
    #[command(flatten)]
    options: Options,
}

impl Disable {
    fn run(self) -> Result {
        let _lock = self.options.lock()?;
        let mut vault = self.options.load()?;
        let sealer = options::open_sealer()?;

        vault.disable_hardware_binding(&self.options.password()?, &*sealer)?;
        self.options.store(&vault)?;

        println!("vault is software-only and portable again");
        Ok(())
    }
}
