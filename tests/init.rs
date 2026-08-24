use super::*;

#[test]
fn init_displays_fingerprint_and_fingerprint_matches() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("test.vault");

    let stdout = gilgamesh(&vault, &["init", "--coinflips", &coinflips()], b"");
    let fingerprint = stdout
        .lines()
        .find_map(|line| line.strip_prefix("fingerprint: "))
        .expect("init should print a fingerprint")
        .to_string();
    assert_eq!(fingerprint.len(), 16);

    assert_eq!(
        gilgamesh(&vault, &["fingerprint"], b"").trim(),
        fingerprint,
        "restore verification must reproduce the creation fingerprint"
    );
}

#[test]
fn init_refuses_to_overwrite_and_requires_one_entropy_source() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    let clobber = run(&vault, PASSWORD, &["init", "--random"], b"");
    assert!(!clobber.status.success());

    let none = run(&dir.path().join("other.vault"), PASSWORD, &["init"], b"");
    assert!(!none.status.success());

    let both = run(
        &dir.path().join("other.vault"),
        PASSWORD,
        &["init", "--random", "--coinflips", &coinflips()],
        b"",
    );
    assert!(!both.status.success());
}

#[test]
fn random_prints_a_mnemonic_backup_that_restores_the_identity() {
    let dir = TempDir::new().unwrap();

    // Non-interactively, --random must be an explicit opt-in.
    let refused = run(
        &dir.path().join("refused.vault"),
        PASSWORD,
        &["init", "--random"],
        b"",
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--yes"));

    let vault = dir.path().join("random.vault");
    let stdout = gilgamesh(&vault, &["init", "--random", "--yes"], b"");
    let mnemonic = stdout
        .lines()
        .find_map(|line| line.strip_prefix("mnemonic: "))
        .expect("--random must print a mnemonic backup");
    assert_eq!(mnemonic.split_whitespace().count(), 24);

    // The mnemonic is the identity's backup: restoring from it must
    // reproduce the fingerprint.
    let restored = dir.path().join("restored.vault");
    gilgamesh(&restored, &["init", "--mnemonic", mnemonic], b"");
    assert_eq!(
        gilgamesh(&vault, &["fingerprint"], b""),
        gilgamesh(&restored, &["fingerprint"], b"")
    );
}

#[test]
fn weak_passwords_require_explicit_approval() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("weak.vault");

    let refused = run(&vault, "hunter22", &["init", "--random", "--yes"], b"");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--allow-weak-password"));

    let approved = run(
        &vault,
        "hunter22",
        &["init", "--random", "--yes", "--allow-weak-password"],
        b"",
    );
    assert!(approved.status.success());
    assert!(String::from_utf8_lossy(&approved.stderr).contains("weak"));
}

#[test]
fn secret_flags_on_argv_warn() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("test.vault");

    let output = run(
        &vault,
        PASSWORD,
        &["init", "--coinflips", &coinflips()],
        b"",
    );
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--coinflips"),
        "raw entropy on argv must be warned about"
    );
}

#[test]
fn wrong_password_fails() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    let output = run(&vault, "wrong password", &["fingerprint"], b"");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("wrong unlock password"));
}

#[test]
fn derivation_passphrase_changes_keys_but_not_fingerprint() {
    let dir = TempDir::new().unwrap();
    let without = init_vault(&dir);

    let passphrase = ["--passphrase", "immutable extra secret"];
    let with = dir.path().join("with-passphrase.vault");
    gilgamesh(
        &with,
        &[
            "init",
            "--coinflips",
            &coinflips(),
            passphrase[0],
            passphrase[1],
        ],
        b"",
    );

    assert_eq!(
        gilgamesh(&with, &["fingerprint", passphrase[0], passphrase[1]], b""),
        gilgamesh(&without, &["fingerprint"], b""),
        "fingerprint identifies the seed, not the passphrase"
    );
    assert_ne!(
        gilgamesh(&with, &["ssh", passphrase[0], passphrase[1]], b""),
        gilgamesh(&without, &["ssh"], b""),
        "the passphrase is part of the identity, so derived keys differ"
    );

    let mismatched = run(&with, PASSWORD, &["ssh"], b"");
    assert!(!mismatched.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched.stderr).contains("integrity"),
        "a wrong derivation passphrase must fail the header tag check"
    );
}
