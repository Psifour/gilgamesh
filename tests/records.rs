use super::*;

#[test]
fn record_roundtrip_ls_and_rm() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    gilgamesh(
        &vault,
        &["put", "peer-alice", "x25519-public-key"],
        b"alice public key",
    );

    assert_eq!(
        gilgamesh(&vault, &["get", "peer-alice"], b""),
        "alice public key"
    );
    assert_eq!(
        gilgamesh(&vault, &["ls"], b""),
        "peer-alice\tx25519-public-key\n"
    );

    gilgamesh(&vault, &["rm", "peer-alice"], b"");
    assert!(gilgamesh(&vault, &["ls"], b"").is_empty());
    assert!(
        !run(&vault, PASSWORD, &["rm", "peer-alice"], b"")
            .status
            .success()
    );
}

#[test]
fn change_password_reseal_keeps_identity_and_records() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    gilgamesh(&vault, &["put", "note"], b"secret");
    let fingerprint = gilgamesh(&vault, &["fingerprint"], b"");

    gilgamesh(
        &vault,
        &[
            "change-password",
            "--new-password",
            "hunter23",
            "--allow-weak-password",
        ],
        b"",
    );

    assert!(
        !run(&vault, PASSWORD, &["fingerprint"], b"")
            .status
            .success()
    );
    assert_eq!(
        run_stdout(&vault, "hunter23", &["fingerprint"]),
        fingerprint
    );
    assert_eq!(run_stdout(&vault, "hunter23", &["get", "note"]), "secret");
}

#[test]
fn change_password_can_change_kdf_params() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    gilgamesh(&vault, &["put", "note"], b"secret");
    gilgamesh(
        &vault,
        &[
            "change-password",
            "--new-password",
            PASSWORD,
            "--kdf-memory",
            "128",
        ],
        b"",
    );

    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&vault).unwrap()).unwrap();
    assert_eq!(json["argon2_params"]["memory_kib"], 128 * 1024);

    assert_eq!(gilgamesh(&vault, &["get", "note"], b""), "secret");
}

#[test]
fn ls_filters_untrusted_ids_to_graphic_ascii() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    // Record ids come back out of an externally editable file: escape
    // sequences must not reach the terminal.
    gilgamesh(&vault, &["put", "esc\x1b]0;owned\x07name"], b"x");

    let listing = gilgamesh(&vault, &["ls"], b"");
    assert!(!listing.contains('\x1b') && !listing.contains('\x07'));
    assert!(listing.contains("esc?]0;owned?name"));
}

#[test]
fn external_record_deletion_warns_loudly_but_does_not_fail() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    gilgamesh(&vault, &["put", "note"], b"secret");

    // Simulate external tampering: delete the record but leave the tag.
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vault).unwrap()).unwrap();
    json["records"].as_array_mut().unwrap().clear();
    std::fs::write(&vault, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

    let output = run(&vault, PASSWORD, &["fingerprint"], b"");
    assert!(output.status.success(), "records integrity is warn-only");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("RECORDS INTEGRITY CHECK FAILED"),
        "external deletion must be called out loudly"
    );
}

#[test]
fn concurrent_puts_are_serialized_not_lost() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);

    // Without the advisory vault lock, concurrent load-modify-store cycles
    // race and the last rename silently discards the other writes.
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let vault = vault.clone();
            std::thread::spawn(move || {
                gilgamesh(&vault, &["put", &format!("record-{i}")], b"payload");
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    let listing = gilgamesh(&vault, &["ls"], b"");
    for i in 0..4 {
        assert!(
            listing.contains(&format!("record-{i}")),
            "record-{i} was lost to a concurrent put; listing:\n{listing}"
        );
    }
}

fn run_stdout(vault: &std::path::Path, password: &str, args: &[&str]) -> String {
    let output = run(vault, password, args, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
