use {
    super::*,
    clap::builder::styling::{AnsiColor, Effects, Styles},
    subcommand::Subcommand,
};

// Flags whose values are secrets. They stay usable for programmatic callers,
// but are hidden from --help and warned about when actually used on argv.
const SENSITIVE_ARGV_FLAGS: &[&str] = &[
    "--coinflips",
    "--dice",
    "--mnemonic",
    "--new-password",
    "--passphrase",
    "--password",
];

fn warn_sensitive_argv() {
    for arg in env::args().skip(1) {
        if let Some(flag) = SENSITIVE_ARGV_FLAGS.iter().find(|flag| {
            arg == **flag
                || arg
                    .strip_prefix(**flag)
                    .is_some_and(|rest| rest.starts_with('='))
        }) {
            eprintln!(
                "warning: {flag} was passed on the command line; its value is visible in shell \
                 history and /proc/*/cmdline. Prefer the environment variable or the \
                 interactive prompt."
            );
        }
    }
}

#[derive(Parser)]
#[command(
  version,
  styles = Styles::styled()
    .error(AnsiColor::Red.on_default() | Effects::BOLD)
    .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
    .invalid(AnsiColor::Red.on_default())
    .literal(AnsiColor::Blue.on_default())
    .placeholder(AnsiColor::Cyan.on_default())
    .usage(AnsiColor::Yellow.on_default() | Effects::BOLD)
    .valid(AnsiColor::Green.on_default()),
)]
pub(crate) struct Arguments {
    #[command(subcommand)]
    pub(crate) subcommand: Subcommand,
}

impl Arguments {
    pub(crate) fn run(self) -> Result {
        warn_sensitive_argv();
        self.subcommand.run()
    }
}
