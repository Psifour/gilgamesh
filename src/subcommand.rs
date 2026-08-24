use super::*;

pub mod agent;
pub mod change_password;
pub mod fingerprint;
pub mod get;
pub mod hardware;
pub mod init;
pub mod ls;
pub mod mnemonic;
pub mod put;
pub mod rm;
pub mod ssh;

#[derive(Parser)]
pub(crate) enum Subcommand {
    #[command(about = "Create a new vault from a raw entropy source")]
    Init(init::Init),
    #[command(about = "Show the seed fingerprint for backup verification")]
    Fingerprint(fingerprint::Fingerprint),
    #[command(about = "Derive an SSH ed25519 key")]
    Ssh(ssh::Ssh),
    #[command(about = "Derive a BIP39 mnemonic")]
    Mnemonic(mnemonic::MnemonicCommand),
    #[command(about = "Encrypt a record from stdin into the vault")]
    Put(put::Put),
    #[command(about = "Decrypt a record to stdout")]
    Get(get::Get),
    #[command(about = "List record ids and types")]
    Ls(ls::Ls),
    #[command(about = "Remove a record")]
    Rm(rm::Rm),
    #[command(about = "Hold the unlocked identity and serve local clients (incl. ssh-agent)")]
    Agent(agent::Agent),
    #[command(about = "Re-seal the seed under a new unlock password")]
    ChangePassword(change_password::ChangePassword),
    #[command(about = "Manage hardware binding of the working copy")]
    Hardware(hardware::Hardware),
}

impl Subcommand {
    pub(crate) fn run(self) -> Result {
        match self {
            Self::Init(init) => init.run(),
            Self::Fingerprint(fingerprint) => fingerprint.run(),
            Self::Ssh(ssh) => ssh.run(),
            Self::Mnemonic(mnemonic) => mnemonic.run(),
            Self::Put(put) => put.run(),
            Self::Get(get) => get.run(),
            Self::Ls(ls) => ls.run(),
            Self::Rm(rm) => rm.run(),
            Self::Agent(agent) => agent.run(),
            Self::ChangePassword(change_password) => change_password.run(),
            Self::Hardware(hardware) => hardware.run(),
        }
    }
}
