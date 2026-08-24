use super::*;

#[test]
fn ssh_keys_are_deterministic_and_openssh_formatted() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    let public = gilgamesh(&vault, &["ssh"], b"");
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(public.trim_end().ends_with("gilgamesh:default"));
    assert_eq!(public, gilgamesh(&vault, &["ssh"], b""));
    assert_ne!(public, gilgamesh(&vault, &["ssh", "github"], b""));

    let private = gilgamesh(&vault, &["ssh", "--private"], b"");
    assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
}

#[test]
fn mnemonic_is_deterministic_24_words() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    let mnemonic = gilgamesh(&vault, &["mnemonic"], b"");
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    assert_eq!(mnemonic, gilgamesh(&vault, &["mnemonic"], b""));
}
