use {
    super::*,
    gilgamesh::{
        RecordsIntegrity, Vault,
        agent::{Client, Config, Server, ssh_socket_path},
        ed25519_dalek::Signature,
    },
    std::{
        fs,
        io::Read,
        os::unix::{
            fs::{DirBuilderExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        thread,
        time::Duration,
    },
};

fn unlock(vault: &Path) -> gilgamesh::Identity {
    Vault::from_bytes(&fs::read(vault).unwrap())
        .unwrap()
        .unlock(PASSWORD, None, None)
        .unwrap()
}

/// A tempdir is created with the default umask (typically 0755), which the
/// agent refuses to serve from; the socket needs a private directory.
fn private(dir: &TempDir) -> PathBuf {
    let private = dir.path().join("run");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .unwrap();
    private
}

fn connect(socket: &Path) -> Client {
    for _ in 0..200 {
        if let Ok(client) = Client::connect(Some(socket)) {
            return client;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("agent socket `{}` never came up", socket.display());
}

fn put_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn put_string(buffer: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buffer, bytes.len() as u32);
    buffer.extend_from_slice(bytes);
}

fn take_u32(cursor: &mut &[u8]) -> u32 {
    let (head, rest) = cursor.split_at(4);
    *cursor = rest;
    u32::from_be_bytes(head.try_into().unwrap())
}

fn take_string<'a>(cursor: &mut &'a [u8]) -> &'a [u8] {
    let len = take_u32(cursor) as usize;
    let (head, rest) = cursor.split_at(len);
    *cursor = rest;
    head
}

fn ssh_roundtrip(stream: &mut UnixStream, message: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(message.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(message).unwrap();

    let mut len = [0; 4];
    stream.read_exact(&mut len).unwrap();
    let mut reply = vec![0; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).unwrap();
    reply
}

#[test]
fn agent_serves_json_and_ssh_clients() {
    let dir = TempDir::new().unwrap();
    let vault_path = init_vault(&dir);

    let identity = unlock(&vault_path);
    let fingerprint = identity.fingerprint();
    let app_key = identity.derive_key("gilgamesh.kms/v1/app/test").unwrap();
    let wallet_seed = identity.wallet_seed("default").unwrap();
    let verifying_key = identity.ssh_keypair("default").unwrap().verifying_key();

    let socket = private(&dir).join("agent.sock");
    let server = Server::new(
        vault_path.clone(),
        identity,
        Config {
            socket: Some(socket.clone()),
            allow_wallet_seed: true,
            ..Config::default()
        },
    )
    .unwrap();
    thread::spawn(move || server.run().unwrap());
    let mut client = connect(&socket);

    let status = client.status().unwrap();
    assert!(!status.locked);
    assert_eq!(status.fingerprint.as_deref(), Some(fingerprint.as_str()));
    // The served public keys are in the status, byte-for-byte what the CLI
    // prints.
    assert_eq!(status.ssh_keys.len(), 1);
    assert_eq!(status.ssh_keys[0].keyname, "default");
    assert_eq!(
        status.ssh_keys[0].public_key,
        gilgamesh(&vault_path, &["ssh"], b"").trim_end()
    );

    assert_eq!(
        *client.derive_app_key("gilgamesh.kms/v1/app/test").unwrap(),
        *app_key
    );
    assert!(
        client
            .derive_app_key("gilgamesh.kms/v1/vault-key")
            .unwrap_err()
            .to_string()
            .contains("reserved"),
        "system labels must be refused over the socket"
    );

    client
        .vault_put("agent-test", "secret", b"hello from the agent")
        .unwrap();
    assert_eq!(
        client.vault_get("agent-test").unwrap().as_slice(),
        b"hello from the agent".as_slice()
    );
    let (records, integrity) = client.vault_list().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.id == "agent-test" && record.record_type == "secret")
    );
    assert_eq!(integrity, RecordsIntegrity::Verified);

    // The CLI sees what the agent wrote: same file, same format, same lock.
    assert_eq!(
        gilgamesh(&vault_path, &["get", "agent-test"], b""),
        "hello from the agent"
    );

    assert_eq!(*client.wallet_seed("default").unwrap(), *wallet_seed);

    assert!(client.vault_rm("agent-test").unwrap());
    assert!(!client.vault_rm("agent-test").unwrap());

    // The ssh-agent protocol on the sibling socket: list the derived key,
    // then verify a signature made in-process. The private key never
    // appears on the wire.
    let mut ssh = UnixStream::connect(ssh_socket_path(&socket)).unwrap();

    let reply = ssh_roundtrip(&mut ssh, &[11]);
    let (&message_type, rest) = reply.split_first().unwrap();
    let mut cursor = rest;
    assert_eq!(message_type, 12, "SSH_AGENT_IDENTITIES_ANSWER");
    assert_eq!(take_u32(&mut cursor), 1);
    let blob = take_string(&mut cursor).to_vec();
    assert_eq!(take_string(&mut cursor), b"gilgamesh:default");
    {
        let mut key = blob.as_slice();
        assert_eq!(take_string(&mut key), b"ssh-ed25519");
        assert_eq!(take_string(&mut key), verifying_key.as_bytes());
    }

    let mut request = vec![13];
    put_string(&mut request, &blob);
    put_string(&mut request, b"data to sign");
    put_u32(&mut request, 0);
    let reply = ssh_roundtrip(&mut ssh, &request);
    let (&message_type, rest) = reply.split_first().unwrap();
    let mut cursor = rest;
    assert_eq!(message_type, 14, "SSH_AGENT_SIGN_RESPONSE");
    let mut signature = take_string(&mut cursor);
    assert_eq!(take_string(&mut signature), b"ssh-ed25519");
    let signature = Signature::from_bytes(take_string(&mut signature).try_into().unwrap());
    verifying_key
        .verify_strict(b"data to sign", &signature)
        .unwrap();

    // Unknown request types fail cleanly.
    assert_eq!(ssh_roundtrip(&mut ssh, &[42]), [5]);

    // Locking drops the identity; a non-interactive agent cannot re-unlock.
    client.lock().unwrap();
    let status = client.status().unwrap();
    assert!(status.locked);
    assert_eq!(status.ssh_keys.len(), 1, "public keys survive locking");
    assert!(
        client
            .derive_app_key("gilgamesh.kms/v1/app/test")
            .unwrap_err()
            .to_string()
            .contains("locked")
    );

    // A locked agent still lists its public keys (no identity needed), but
    // cannot sign.
    let reply = ssh_roundtrip(&mut ssh, &[11]);
    let (&message_type, rest) = reply.split_first().unwrap();
    let mut cursor = rest;
    assert_eq!(message_type, 12, "listing works while locked");
    assert_eq!(take_u32(&mut cursor), 1);
    assert_eq!(take_string(&mut cursor), blob.as_slice());
    assert_eq!(
        ssh_roundtrip(&mut ssh, &request),
        [5],
        "signing fails while locked"
    );
}

fn server(vault_path: &Path, socket: &Path, config: Config) -> Server {
    Server::new(
        vault_path.to_path_buf(),
        unlock(vault_path),
        Config {
            socket: Some(socket.to_path_buf()),
            ..config
        },
    )
    .unwrap()
}

#[test]
fn stale_socket_is_replaced_but_a_regular_file_is_not() {
    let dir = TempDir::new().unwrap();
    let vault_path = init_vault(&dir);

    let run = private(&dir);

    // Something that is not a socket at the socket path: refused, untouched.
    let socket = run.join("file.sock");
    fs::write(&socket, b"not a socket").unwrap();
    let err = server(&vault_path, &socket, Config::default())
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a socket"), "{err}");
    assert_eq!(fs::read(&socket).unwrap(), b"not a socket");

    // The same for the ssh sibling.
    let socket = run.join("sibling.sock");
    fs::write(ssh_socket_path(&socket), b"not a socket").unwrap();
    let err = server(&vault_path, &socket, Config::default())
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a socket"), "{err}");

    // A socket nobody listens on (a dead agent's) is replaced.
    let socket = run.join("stale.sock");
    drop(UnixListener::bind(&socket).unwrap());
    drop(UnixListener::bind(ssh_socket_path(&socket)).unwrap());
    let server = server(&vault_path, &socket, Config::default());
    thread::spawn(move || server.run().unwrap());
    assert!(!connect(&socket).status().unwrap().locked);

    // A live agent's socket is not.
    let err = self::server(&vault_path, &socket, Config::default())
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("already listening"), "{err}");
}

#[test]
fn insecure_socket_dir_is_refused_unless_allowed() {
    let dir = TempDir::new().unwrap();
    let vault_path = init_vault(&dir);

    let shared = dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    let socket = shared.join("agent.sock");

    let err = server(&vault_path, &socket, Config::default())
        .run()
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a private (0700) directory"), "{err}");
    assert!(err.contains("--allow-insecure-socket-dir"), "{err}");
    assert!(!socket.exists(), "refused before binding");

    let server = server(
        &vault_path,
        &socket,
        Config {
            allow_insecure_socket_dir: true,
            ..Config::default()
        },
    );
    thread::spawn(move || server.run().unwrap());
    assert!(!connect(&socket).status().unwrap().locked);

    // A missing directory is created private.
    let socket = dir.path().join("fresh").join("agent.sock");
    let server = self::server(&vault_path, &socket, Config::default());
    thread::spawn(move || server.run().unwrap());
    connect(&socket);
    assert_eq!(
        fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn idle_timeout_locks_the_identity() {
    let dir = TempDir::new().unwrap();
    let vault_path = init_vault(&dir);
    let identity = unlock(&vault_path);

    let socket = private(&dir).join("timeout.sock");
    let server = Server::new(
        vault_path,
        identity,
        Config {
            socket: Some(socket.clone()),
            timeout: Some(Duration::from_secs(1)),
            ..Config::default()
        },
    )
    .unwrap();
    thread::spawn(move || server.run().unwrap());
    let mut client = connect(&socket);

    assert!(!client.status().unwrap().locked);
    thread::sleep(Duration::from_secs(3));
    assert!(
        client.status().unwrap().locked,
        "the identity must be dropped after the idle timeout"
    );
}
