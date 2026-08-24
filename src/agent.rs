//! Session agent: holds one unlocked [`Identity`] and serves it to local
//! clients over two uid-checked Unix sockets, so applications never see the
//! unlock password and never hold key material longer than one operation.
//!
//! Two sockets, side by side:
//!
//! - `agent.sock` — length-prefixed (u32 BE) JSON [`Request`]/[`Response`]
//!   frames, one request per frame, many frames per connection. Operations
//!   cover app-key derivation (`app/` namespace only), vault records, and
//!   the wallet seed (confirmation-gated).
//! - `agent.ssh.sock` — the ssh-agent wire protocol. Derived ssh keys are
//!   listed and used for signing in-process: private keys never cross any
//!   socket; clients receive signatures only. Point `SSH_AUTH_SOCK` (or a
//!   per-host `IdentityAgent`) at it. Public keys are computed once at
//!   startup and served even while locked; only signing needs the identity.
//!
//! Never served: the seed, the derivation passphrase, system derivation
//! labels (`vault-key`, `mac-key`, ...), or raw ssh/codesign private keys.
//!
//! Secrets that do cross the JSON socket (app keys, record plaintext, the
//! wallet seed) ride in zeroized buffers on both ends — best-effort:
//! transient copies inside the JSON serializer and base64 encoder are
//! outside zeroize's reach, exactly like the transient stack copies
//! documented in `memlock`.

use {
    super::*,
    ed25519_dalek::Signer,
    std::{
        os::{
            fd::AsRawFd,
            unix::{
                fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
                net::{UnixListener, UnixStream},
            },
        },
        path::Path,
        sync::{Arc, Mutex, MutexGuard, PoisonError},
        thread,
        time::{Duration, Instant},
    },
};

/// Upper bound on a single frame, both directions and both protocols.
const MAX_FRAME: usize = 4 * 1024 * 1024;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// One client request. Every operation that needs the identity re-unlocks at
/// the agent's terminal if the idle timeout has locked it (interactive
/// agents only).
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Agent and identity state. Never touches (or re-unlocks) the identity.
    Status,
    /// Drop the unlocked identity now.
    Lock,
    /// HKDF-expand an application label. The label must live under
    /// [`APP_NAMESPACE`]; system labels are refused, exactly as
    /// [`Identity::derive_key`] refuses them.
    DeriveAppKey {
        label: String,
    },
    /// Ids and types of every record, plus the integrity of the set.
    VaultList,
    VaultGet {
        id: String,
    },
    VaultPut {
        id: String,
        record_type: String,
        #[serde(with = "b64z")]
        plaintext: Zeroizing<Vec<u8>>,
    },
    VaultRm {
        id: String,
    },
    /// The 64-byte BIP39 wallet seed for `keyname`. Non-app derived key
    /// material: gated behind per-request confirmation at the agent's
    /// terminal unless the agent allows it unconditionally
    /// (`--allow-wallet-seed`).
    WalletSeed {
        keyname: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Response {
    Status(Status),
    Done,
    Key {
        #[serde(with = "b64z")]
        key: Zeroizing<Vec<u8>>,
    },
    Records {
        records: Vec<RecordInfo>,
        integrity: RecordsIntegrity,
    },
    Plaintext {
        #[serde(with = "b64z")]
        plaintext: Zeroizing<Vec<u8>>,
    },
    Removed {
        removed: bool,
    },
    Seed {
        #[serde(with = "b64z")]
        seed: Zeroizing<Vec<u8>>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Status {
    pub locked: bool,
    /// Present only while unlocked.
    pub fingerprint: Option<String>,
    pub vault: String,
    /// The ssh keys served on the sibling socket. Public, so available
    /// while locked.
    pub ssh_keys: Vec<SshPublicKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshPublicKey {
    pub keyname: String,
    /// One `authorized_keys` line: `ssh-ed25519 <base64> gilgamesh:<keyname>`.
    pub public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RecordInfo {
    pub id: String,
    pub record_type: String,
}

/// Like `b64`, but decodes into (and serializes from) zeroizing buffers:
/// these fields carry key material and record plaintext.
mod b64z {
    use super::*;

    pub fn serialize<S: Serializer>(
        bytes: &Zeroizing<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes.as_slice()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let string = String::deserialize(deserializer)?;
        BASE64
            .decode(&string)
            .map(Zeroizing::new)
            .map_err(serde::de::Error::custom)
    }
}

/// Default agent socket: `$XDG_RUNTIME_DIR/gilgamesh/agent.sock`, or a
/// uid-scoped directory under the system temp dir where `XDG_RUNTIME_DIR` is
/// absent (macOS). The uid in the fallback name keeps users apart on a
/// shared temp dir.
pub fn default_socket_path() -> PathBuf {
    let dir = match env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("gilgamesh"),
        _ => env::temp_dir().join(format!("gilgamesh-{}", uid())),
    };
    dir.join("agent.sock")
}

/// The ssh-agent socket sits beside the JSON socket:
/// `agent.sock` → `agent.ssh.sock`.
pub fn ssh_socket_path(socket: &Path) -> PathBuf {
    socket.with_extension("ssh.sock")
}

fn uid() -> u32 {
    // SAFETY: getuid cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

/// Client side of the JSON protocol. One request/response pair per call; the
/// connection stays open across calls.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Connect to the agent at `socket`, or at [`default_socket_path`].
    pub fn connect(socket: Option<&Path>) -> Result<Self> {
        let path = socket.map_or_else(default_socket_path, Path::to_path_buf);
        let stream = UnixStream::connect(&path).with_context(|| {
            format!(
                "failed to connect to agent socket `{}` (is `gilgamesh agent` running?)",
                path.display()
            )
        })?;
        Ok(Self { stream })
    }

    pub fn status(&mut self) -> Result<Status> {
        match self.call(&Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => bail!("unexpected reply from agent"),
        }
    }

    pub fn lock(&mut self) -> Result {
        match self.call(&Request::Lock)? {
            Response::Done => Ok(()),
            _ => bail!("unexpected reply from agent"),
        }
    }

    /// Derive an application key. `label` must start with [`APP_NAMESPACE`].
    pub fn derive_app_key(&mut self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        match self.call(&Request::DeriveAppKey {
            label: label.into(),
        })? {
            Response::Key { key } => {
                ensure!(
                    key.len() == 32,
                    "agent returned a key of {} bytes",
                    key.len()
                );
                let mut out = Zeroizing::new([0; 32]);
                out.copy_from_slice(&key);
                Ok(out)
            }
            _ => bail!("unexpected reply from agent"),
        }
    }

    pub fn vault_list(&mut self) -> Result<(Vec<RecordInfo>, RecordsIntegrity)> {
        match self.call(&Request::VaultList)? {
            Response::Records { records, integrity } => Ok((records, integrity)),
            _ => bail!("unexpected reply from agent"),
        }
    }

    pub fn vault_get(&mut self, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        match self.call(&Request::VaultGet { id: id.into() })? {
            Response::Plaintext { plaintext } => Ok(plaintext),
            _ => bail!("unexpected reply from agent"),
        }
    }

    pub fn vault_put(&mut self, id: &str, record_type: &str, plaintext: &[u8]) -> Result {
        match self.call(&Request::VaultPut {
            id: id.into(),
            record_type: record_type.into(),
            plaintext: Zeroizing::new(plaintext.to_vec()),
        })? {
            Response::Done => Ok(()),
            _ => bail!("unexpected reply from agent"),
        }
    }

    pub fn vault_rm(&mut self, id: &str) -> Result<bool> {
        match self.call(&Request::VaultRm { id: id.into() })? {
            Response::Removed { removed } => Ok(removed),
            _ => bail!("unexpected reply from agent"),
        }
    }

    pub fn wallet_seed(&mut self, keyname: &str) -> Result<Zeroizing<[u8; 64]>> {
        match self.call(&Request::WalletSeed {
            keyname: keyname.into(),
        })? {
            Response::Seed { seed } => {
                ensure!(
                    seed.len() == 64,
                    "agent returned a seed of {} bytes",
                    seed.len()
                );
                let mut out = Zeroizing::new([0; 64]);
                out.copy_from_slice(&seed);
                Ok(out)
            }
            _ => bail!("unexpected reply from agent"),
        }
    }

    fn call(&mut self, request: &Request) -> Result<Response> {
        let frame = Zeroizing::new(serde_json::to_vec(request)?);
        write_frame(&mut self.stream, &frame)?;
        let frame =
            read_frame(&mut self.stream)?.ok_or_else(|| anyhow!("agent closed the connection"))?;
        match serde_json::from_slice(&frame)? {
            Response::Error { message } => bail!("agent: {message}"),
            response => Ok(response),
        }
    }
}

/// Agent configuration. `interactive` should be true only when the agent's
/// stdin is a terminal a human is watching: it enables re-unlock prompts,
/// wallet-seed confirmations, and per-signature ssh confirmations.
#[derive(Debug)]
pub struct Config {
    /// JSON socket path; `None` means [`default_socket_path`]. The ssh-agent
    /// socket always sits beside it ([`ssh_socket_path`]).
    pub socket: Option<PathBuf>,
    /// Drop the identity after this much idle time; `None` keeps it for the
    /// agent's lifetime.
    pub timeout: Option<Duration>,
    /// Serve wallet-seed requests without per-request confirmation.
    pub allow_wallet_seed: bool,
    /// Serve from a socket directory that is not a private (0700)
    /// directory owned by this user, with a warning instead of a refusal.
    /// Clients do not authenticate the agent, so whoever controls the
    /// directory can swap the socket and receive what clients send.
    pub allow_insecure_socket_dir: bool,
    /// Confirm every ssh signature at the agent's terminal.
    pub confirm_ssh: bool,
    /// Keynames served over the ssh-agent socket.
    pub ssh_keynames: Vec<String>,
    /// Re-prompt for the derivation passphrase on re-unlock (the agent never
    /// retains it).
    pub ask_passphrase: bool,
    pub interactive: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket: None,
            timeout: None,
            allow_wallet_seed: false,
            allow_insecure_socket_dir: false,
            confirm_ssh: false,
            ssh_keynames: vec!["default".into()],
            ask_passphrase: false,
            interactive: false,
        }
    }
}

pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    vault: PathBuf,
    socket: PathBuf,
    ssh_socket: PathBuf,
    config: Config,
    /// Public halves of the served ssh keys, computed once at startup so
    /// listing them never needs (or re-unlocks) the identity.
    ssh_keys: Vec<SshKey>,
    state: Mutex<State>,
}

struct SshKey {
    keyname: String,
    /// The ssh wire encoding of the public key.
    blob: Vec<u8>,
    /// The `authorized_keys` form of the same key.
    openssh: String,
}

struct State {
    identity: Option<Identity>,
    last_used: Instant,
}

impl Server {
    pub fn new(vault: PathBuf, identity: Identity, config: Config) -> Result<Self> {
        // Fail on a bad --ssh-key at startup, not at the first sign request.
        let ssh_keys = config
            .ssh_keynames
            .iter()
            .map(|keyname| {
                let keypair = identity
                    .ssh_keypair(keyname)
                    .with_context(|| format!("invalid ssh keyname `{}`", sanitize(keyname)))?;
                let blob = ed25519_blob(&keypair);
                let mut public_key = ssh_key::PublicKey::from_bytes(&blob)?;
                public_key.set_comment(format!("gilgamesh:{keyname}"));
                Ok(SshKey {
                    keyname: keyname.clone(),
                    blob,
                    openssh: public_key.to_openssh()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let socket = config.socket.clone().unwrap_or_else(default_socket_path);
        let ssh_socket = ssh_socket_path(&socket);

        Ok(Self {
            inner: Arc::new(Inner {
                vault,
                socket,
                ssh_socket,
                config,
                ssh_keys,
                state: Mutex::new(State {
                    identity: Some(identity),
                    last_used: Instant::now(),
                }),
            }),
        })
    }

    /// Serve until the process exits. Every connection's peer uid is checked
    /// before any frame is read.
    pub fn run(self) -> Result {
        let inner = self.inner;

        prepare_socket_dir(&inner.socket, inner.config.allow_insecure_socket_dir)?;

        // A 0177 umask makes the sockets 0600 from the instant they exist —
        // no window between bind and chmod. umask is process-global, so any
        // file another thread creates during these two binds is masked the
        // same way; that is harmless (over-restrictive, never permissive),
        // and the CLI has no other threads here anyway.
        // SAFETY: umask cannot fail and touches no memory.
        let old_umask = unsafe { libc::umask(0o177) };
        let listener = bind(&inner.socket);
        let ssh_listener = bind(&inner.ssh_socket);
        unsafe {
            libc::umask(old_umask);
        }
        let (listener, ssh_listener) = (listener?, ssh_listener?);

        eprintln!("agent: GILGAMESH_AGENT_SOCK={}", inner.socket.display());
        eprintln!("agent: SSH_AUTH_SOCK={}", inner.ssh_socket.display());

        // TODO(design-doc): lock on suspend, best effort. Needs a platform suspend signal
        if inner.config.timeout.is_some() {
            let inner = inner.clone();
            thread::spawn(move || idle_locker(&inner));
        }

        {
            let inner = inner.clone();
            thread::spawn(move || accept_loop(&inner, ssh_listener, true));
        }
        accept_loop(&inner, listener, false);
        Ok(())
    }
}

fn idle_locker(inner: &Inner) {
    let Some(timeout) = inner.config.timeout else {
        return;
    };
    loop {
        thread::sleep(Duration::from_secs(1));
        let mut state = inner.state();
        if state.identity.is_some() && state.last_used.elapsed() >= timeout {
            state.identity = None;
            eprintln!("agent: locked after {}s idle", timeout.as_secs());
        }
    }
}

/// Create the socket's parent directory 0700 when missing, and refuse to
/// serve from one that is not a private directory owned by this user.
/// Every connection's peer uid is verified, so a foreign directory cannot
/// admit foreign *clients* — but clients never authenticate the *agent*, and
/// whoever controls the directory can replace the socket with their own and
/// receive whatever clients send (record plaintext, on `vault_put`). With
/// `allow_insecure` the refusal becomes a warning; the user keeps the final
/// say.
fn prepare_socket_dir(socket: &Path, allow_insecure: bool) -> Result {
    let Some(dir) = socket.parent().filter(|dir| !dir.as_os_str().is_empty()) else {
        return Ok(());
    };

    if !dir.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(dir)
            .with_context(|| format!("failed to create socket directory `{}`", dir.display()))?;
    }

    let metadata = fs::metadata(dir)
        .with_context(|| format!("failed to inspect socket directory `{}`", dir.display()))?;
    if metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
        let problem = format!(
            "socket directory `{}` is not a private (0700) directory owned by you",
            dir.display()
        );
        ensure!(
            allow_insecure,
            "{problem}; another user could swap the socket for their own. \
             Use --socket to pick a private directory, or --allow-insecure-socket-dir to \
             serve here anyway"
        );
        eprintln!("warning: {problem}; serving anyway (--allow-insecure-socket-dir)");
    }
    Ok(())
}

/// Bind, replacing a stale socket left by a dead agent; refuse when a live
/// agent answers on it, and refuse to touch anything that is not a socket.
fn bind(path: &Path) -> Result<UnixListener> {
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            ensure!(
                fs::symlink_metadata(path)
                    .map(|metadata| metadata.file_type().is_socket())
                    .unwrap_or(false),
                "`{}` exists and is not a socket; refusing to replace it",
                path.display()
            );
            ensure!(
                UnixStream::connect(path).is_err(),
                "an agent is already listening on `{}`",
                path.display()
            );
            fs::remove_file(path)
                .with_context(|| format!("failed to remove stale socket `{}`", path.display()))?;
            UnixListener::bind(path)
                .with_context(|| format!("failed to bind `{}`", path.display()))?
        }
        Err(err) => {
            return Err(err).with_context(|| format!("failed to bind `{}`", path.display()));
        }
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn accept_loop(inner: &Arc<Inner>, listener: UnixListener, ssh: bool) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };

        // Same-uid only. Yama-style ptrace restrictions mean same-uid
        // processes cannot necessarily read each other's memory, so this
        // boundary is worth having even though it admits every process of
        // the user.
        match peer_uid(&stream) {
            Ok(peer) if peer == uid() => {}
            Ok(peer) => {
                eprintln!("agent: rejected connection from uid {peer}");
                continue;
            }
            Err(err) => {
                eprintln!("agent: failed to read peer credentials: {err:#}");
                continue;
            }
        }

        let inner = inner.clone();
        thread::spawn(move || {
            let served = if ssh {
                serve_ssh(&inner, stream)
            } else {
                serve_json(&inner, stream)
            };
            if let Err(err) = served {
                eprintln!("agent: connection failed: {err:#}");
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for writes of the sizes passed.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    };
    ensure!(
        rc == 0,
        "SO_PEERCRED failed: {}",
        io::Error::last_os_error()
    );
    Ok(cred.uid)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let (mut euid, mut egid) = (0, 0);
    // SAFETY: euid and egid are valid for writes.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    ensure!(rc == 0, "getpeereid failed: {}", io::Error::last_os_error());
    Ok(euid)
}

fn serve_json(inner: &Inner, mut stream: UnixStream) -> Result {
    while let Some(frame) = read_frame(&mut stream)? {
        let response = match serde_json::from_slice(&frame) {
            Ok(request) => inner.handle(request),
            Err(err) => Response::Error {
                message: format!("malformed request: {err}"),
            },
        };
        let frame = Zeroizing::new(serde_json::to_vec(&response)?);
        write_frame(&mut stream, &frame)?;
    }
    Ok(())
}

fn serve_ssh(inner: &Inner, mut stream: UnixStream) -> Result {
    while let Some(frame) = read_frame(&mut stream)? {
        write_frame(&mut stream, &inner.ssh_reply(&frame))?;
    }
    Ok(())
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `operation` against the unlocked identity, re-unlocking at the
    /// agent's terminal if the idle timeout has locked it. The state lock is
    /// held throughout, which serializes identity use — including terminal
    /// prompts — across client connections.
    fn with_identity<T>(&self, operation: impl FnOnce(&Identity) -> Result<T>) -> Result<T> {
        let mut state = self.state();

        if state.identity.is_none() {
            ensure!(
                self.config.interactive,
                "agent is locked (idle timeout) and cannot prompt; restart it from a terminal"
            );
            eprintln!("agent: locked; a client needs the identity");
            let (_, identity) = self.cli_options().unlock()?;
            eprintln!("agent: unlocked {}", identity.fingerprint());
            state.identity = Some(identity);
        }
        state.last_used = Instant::now();

        operation(state.identity.as_ref().expect("identity was just ensured"))
    }

    /// Options equivalent to the CLI's for this vault, re-reading the secret
    /// environment variables the way clap would. The password itself is
    /// never retained between unlocks.
    fn cli_options(&self) -> Options {
        Options {
            vault: self.vault.clone(),
            password: env::var("GILGAMESH_PASSWORD").ok().map(Zeroizing::new),
            passphrase: env::var("GILGAMESH_PASSPHRASE").ok().map(Zeroizing::new),
            ask_passphrase: self.config.ask_passphrase,
        }
    }

    fn handle(&self, request: Request) -> Response {
        self.dispatch(request)
            .unwrap_or_else(|err| Response::Error {
                message: format!("{err:#}"),
            })
    }

    fn dispatch(&self, request: Request) -> Result<Response> {
        match request {
            Request::Status => {
                let state = self.state();
                Ok(Response::Status(Status {
                    locked: state.identity.is_none(),
                    fingerprint: state.identity.as_ref().map(Identity::fingerprint),
                    vault: self.vault.display().to_string(),
                    ssh_keys: self.ssh_public_keys(),
                }))
            }
            Request::Lock => {
                if self.state().identity.take().is_some() {
                    eprintln!("agent: locked by request");
                }
                Ok(Response::Done)
            }
            Request::DeriveAppKey { label } => self.with_identity(|identity| {
                Ok(Response::Key {
                    key: Zeroizing::new(identity.derive_key(&label)?.to_vec()),
                })
            }),
            // Vault operations reload the file every time — the CLI or other
            // tools may have rewritten it — and verify the loaded vault
            // belongs to the held identity, so a swapped vault file is
            // refused instead of corrupted.
            Request::VaultList => self.with_identity(|identity| {
                let vault = self.cli_options().load()?;
                vault.verify_identity(identity)?;
                Ok(Response::Records {
                    records: vault
                        .records()
                        .iter()
                        .map(|record| RecordInfo {
                            id: record.id().into(),
                            record_type: record.record_type().into(),
                        })
                        .collect(),
                    integrity: vault.verify_records(identity),
                })
            }),
            Request::VaultGet { id } => self.with_identity(|identity| {
                let vault = self.cli_options().load()?;
                vault.verify_identity(identity)?;
                Ok(Response::Plaintext {
                    plaintext: vault.get(identity, &id)?,
                })
            }),
            Request::VaultPut {
                id,
                record_type,
                plaintext,
            } => self.with_identity(|identity| {
                let options = self.cli_options();
                let _lock = options.lock()?;
                let mut vault = options.load()?;
                vault.verify_identity(identity)?;
                vault.put(identity, &id, &record_type, &plaintext)?;
                options.store(&vault)?;
                Ok(Response::Done)
            }),
            Request::VaultRm { id } => self.with_identity(|identity| {
                let options = self.cli_options();
                let _lock = options.lock()?;
                let mut vault = options.load()?;
                vault.verify_identity(identity)?;
                let removed = vault.remove(identity, &id);
                if removed {
                    options.store(&vault)?;
                }
                Ok(Response::Removed { removed })
            }),
            Request::WalletSeed { keyname } => self.with_identity(|identity| {
                if !self.config.allow_wallet_seed {
                    ensure!(
                        self.config.interactive,
                        "wallet seed requests need confirmation at the agent's terminal; \
                         start the agent from a terminal or with --allow-wallet-seed"
                    );
                    ensure!(
                        options::confirm(
                            &format!(
                                "agent: a client requests the BIP39 wallet seed for keyname \
                                 `{}`; hand it out?",
                                sanitize(&keyname)
                            ),
                            false
                        )?,
                        "wallet seed request denied at the agent's terminal"
                    );
                }
                Ok(Response::Seed {
                    seed: Zeroizing::new(identity.wallet_seed(&keyname)?.to_vec()),
                })
            }),
        }
    }

    fn ssh_public_keys(&self) -> Vec<SshPublicKey> {
        self.ssh_keys
            .iter()
            .map(|key| SshPublicKey {
                keyname: key.keyname.clone(),
                public_key: key.openssh.clone(),
            })
            .collect()
    }

    fn ssh_reply(&self, frame: &[u8]) -> Vec<u8> {
        self.ssh_dispatch(frame).unwrap_or_else(|err| {
            eprintln!("agent: ssh request failed: {err:#}");
            vec![SSH_AGENT_FAILURE]
        })
    }

    fn ssh_dispatch(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let (&message_type, body) = frame.split_first().context("empty ssh-agent message")?;
        match message_type {
            // Public keys only: answered from the startup cache, so `ssh`
            // probing a locked agent neither fails nor triggers a re-unlock
            // prompt. Only signing needs the identity.
            SSH_AGENTC_REQUEST_IDENTITIES => {
                let mut reply = vec![SSH_AGENT_IDENTITIES_ANSWER];
                put_u32(&mut reply, u32::try_from(self.ssh_keys.len())?);
                for key in &self.ssh_keys {
                    put_string(&mut reply, &key.blob);
                    put_string(&mut reply, format!("gilgamesh:{}", key.keyname).as_bytes());
                }
                Ok(reply)
            }
            SSH_AGENTC_SIGN_REQUEST => {
                let mut cursor = body;
                let blob = take_string(&mut cursor)?;
                let data = take_string(&mut cursor)?;
                // Flags select RSA hash variants; ed25519 has none.
                let _flags = take_u32(&mut cursor)?;

                let keyname = &self
                    .ssh_keys
                    .iter()
                    .find(|key| key.blob == blob)
                    .context("ssh sign request for a key this agent does not serve")?
                    .keyname;

                if self.config.confirm_ssh {
                    ensure!(
                        self.config.interactive,
                        "--confirm-ssh requires the agent to run on a terminal"
                    );
                    ensure!(
                        options::confirm(
                            &format!(
                                "agent: sign an ssh challenge with key `{}`?",
                                sanitize(keyname)
                            ),
                            false
                        )?,
                        "ssh signature denied at the agent's terminal"
                    );
                }

                let signature =
                    self.with_identity(|identity| Ok(identity.ssh_keypair(keyname)?.sign(data)))?;
                let mut blob = Vec::new();
                put_string(&mut blob, b"ssh-ed25519");
                put_string(&mut blob, &signature.to_bytes());
                let mut reply = vec![SSH_AGENT_SIGN_RESPONSE];
                put_string(&mut reply, &blob);
                Ok(reply)
            }
            // Everything else — adding, removing, locking, extensions — is
            // outside this agent's model: keys are derived, not managed.
            _ => Ok(vec![SSH_AGENT_FAILURE]),
        }
    }
}

/// The ssh wire encoding of an ed25519 public key.
fn ed25519_blob(keypair: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, keypair.verifying_key().as_bytes());
    blob
}

fn put_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn put_string(buffer: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(
        buffer,
        u32::try_from(bytes.len()).expect("frame cap keeps strings under u32::MAX"),
    );
    buffer.extend_from_slice(bytes);
}

fn take_u32(cursor: &mut &[u8]) -> Result<u32> {
    ensure!(cursor.len() >= 4, "truncated ssh-agent message");
    let (head, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_be_bytes(head.try_into().expect("split_at(4)")))
}

fn take_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = take_u32(cursor)? as usize;
    ensure!(cursor.len() >= len, "truncated ssh-agent message");
    let (head, rest) = cursor.split_at(len);
    *cursor = rest;
    Ok(head)
}

fn write_frame(stream: &mut impl Write, frame: &[u8]) -> Result {
    ensure!(frame.len() <= MAX_FRAME, "frame exceeds {MAX_FRAME} bytes");
    stream.write_all(&(frame.len() as u32).to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

/// `None` on clean EOF before a length prefix; an error on EOF mid-frame.
fn read_frame(stream: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0; 4];
    match stream.read_exact(&mut len) {
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        result => result?,
    }
    let len = u32::from_be_bytes(len) as usize;
    ensure!(
        len <= MAX_FRAME,
        "frame of {len} bytes exceeds the {MAX_FRAME}-byte limit"
    );
    let mut frame = Zeroizing::new(vec![0; len]);
    stream.read_exact(&mut frame)?;
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_enforce_the_cap() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"hello").unwrap();

        let mut cursor = buffer.as_slice();
        assert_eq!(
            read_frame(&mut cursor).unwrap().unwrap().as_slice(),
            b"hello".as_slice()
        );
        assert!(read_frame(&mut cursor).unwrap().is_none());

        let oversized = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert!(read_frame(&mut oversized.as_slice()).is_err());
    }

    #[test]
    fn ssh_wire_helpers_roundtrip() {
        let mut buffer = Vec::new();
        put_string(&mut buffer, b"ssh-ed25519");
        put_u32(&mut buffer, 7);

        let mut cursor = buffer.as_slice();
        assert_eq!(take_string(&mut cursor).unwrap(), b"ssh-ed25519");
        assert_eq!(take_u32(&mut cursor).unwrap(), 7);
        assert!(take_u32(&mut cursor).is_err());
    }
}
