use {
    std::{
        io::Write,
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
    },
    tempfile::TempDir,
};

#[cfg(unix)]
mod agent;
mod init;
mod keys;
mod records;

const PASSWORD: &str = "correct horse battery staple";

fn coinflips() -> String {
    "01".repeat(64)
}

fn run(vault: &Path, password: &str, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gilgamesh"))
        .args(args)
        .env("GILGAMESH_VAULT", vault)
        .env("GILGAMESH_PASSWORD", password)
        .env_remove("GILGAMESH_PASSPHRASE")
        .env_remove("GILGAMESH_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();

    child.wait_with_output().unwrap()
}

fn gilgamesh(vault: &Path, args: &[&str], stdin: &[u8]) -> String {
    let output = run(vault, PASSWORD, args, stdin);
    assert!(
        output.status.success(),
        "`gilgamesh {}` failed:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).unwrap()
}

fn init_vault(dir: &TempDir) -> PathBuf {
    let vault = dir.path().join("test.vault");
    gilgamesh(&vault, &["init", "--coinflips", &coinflips()], b"");
    vault
}
