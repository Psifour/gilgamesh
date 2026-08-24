use super::*;

#[derive(Parser)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Agent {
    #[command(flatten)]
    options: Options,
    #[arg(
        long,
        env = "GILGAMESH_AGENT_SOCK",
        help = "Serve on socket <PATH>; the ssh-agent socket sits beside it as `*.ssh.sock`. \
                Defaults to $XDG_RUNTIME_DIR/gilgamesh/agent.sock."
    )]
    socket: Option<PathBuf>,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 900,
        help = "Lock the identity after <SECONDS> idle; 0 keeps it unlocked until exit."
    )]
    timeout: u64,
    #[arg(
        long,
        help = "Serve wallet-seed requests without per-request confirmation at the terminal."
    )]
    allow_wallet_seed: bool,
    #[arg(
        long,
        help = "Serve even if the socket directory is not a private (0700) directory owned by \
                you. Whoever controls the directory can swap the socket for their own."
    )]
    allow_insecure_socket_dir: bool,
    #[arg(long, help = "Confirm every ssh signature at the agent's terminal.")]
    confirm_ssh: bool,
    #[arg(
        long = "ssh-key",
        value_name = "KEYNAME",
        help = "Serve the derived ssh key <KEYNAME> (repeatable; default: `default`)."
    )]
    ssh_keys: Vec<String>,
    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Parser)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) enum Action {
    #[command(about = "Show a running agent's state")]
    Status,
    #[command(about = "Make a running agent drop its unlocked identity")]
    Lock,
}

impl Agent {
    #[cfg(unix)]
    pub(crate) fn run(self) -> Result {
        use crate::agent::{Client, Config, Server};

        match self.action {
            Some(Action::Status) => {
                let status = Client::connect(self.socket.as_deref())?.status()?;
                println!("vault: {}", status.vault);
                match status.fingerprint {
                    Some(fingerprint) => println!("state: unlocked ({fingerprint})"),
                    None => println!("state: locked"),
                }
                for key in status.ssh_keys {
                    println!("ssh: {}", key.public_key);
                }
                Ok(())
            }
            Some(Action::Lock) => {
                Client::connect(self.socket.as_deref())?.lock()?;
                eprintln!("agent locked");
                Ok(())
            }
            None => {
                let (_, identity) = self.options.unlock()?;
                eprintln!("agent: unlocked {}", identity.fingerprint());

                Server::new(
                    self.options.vault.clone(),
                    identity,
                    Config {
                        socket: self.socket,
                        timeout: (self.timeout != 0)
                            .then(|| std::time::Duration::from_secs(self.timeout)),
                        allow_wallet_seed: self.allow_wallet_seed,
                        allow_insecure_socket_dir: self.allow_insecure_socket_dir,
                        confirm_ssh: self.confirm_ssh,
                        ssh_keynames: if self.ssh_keys.is_empty() {
                            vec!["default".into()]
                        } else {
                            self.ssh_keys
                        },
                        ask_passphrase: self.options.ask_passphrase,
                        interactive: options::stdin_is_interactive(),
                    },
                )?
                .run()
            }
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn run(self) -> Result {
        bail!(
            "the agent is not yet implemented on this platform (a named-pipe transport is planned)"
        );
    }
}
