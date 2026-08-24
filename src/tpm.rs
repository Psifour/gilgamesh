use {
    super::*,
    std::sync::{Mutex, PoisonError},
    tpm2_protocol::{
        TpmField, TpmWriter,
        basic::{TpmHandle, TpmUint16, TpmUint32},
        constant::TPM_MAX_COMMAND_SIZE,
        data::{
            Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic,
            Tpm2bPublicWire, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId, TpmCap, TpmCc,
            TpmEccCurve, TpmPt, TpmRh, TpmSt, TpmaObject, TpmaSession, TpmiYesNo, TpmlPcrSelection,
            TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms, TpmsSensitiveCreate,
            TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtSymDefObject,
            TpmuAsymScheme, TpmuCapabilities, TpmuCapabilitiesView, TpmuKdfScheme,
            TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicIdView, TpmuPublicParms, TpmuSymKeyBits,
            TpmuSymMode,
        },
        frame::{
            TpmCreateCommand, TpmCreatePrimaryCommand, TpmFlushContextCommand, TpmFrame,
            TpmGetCapabilityCommand, TpmLoadCommand, TpmResponse, TpmResponseOutcome,
            TpmResponseView, TpmUnsealCommand, tpm_marshal_command,
        },
    },
};

const BLOB_MAGIC: &[u8] = b"gilgamesh.kms/v1/tpm2-blob/";

/// Strictly request/response: one `transceive` per TPM command frame.
pub trait TpmTransport {
    fn transceive(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize>;
}

/// Kernel resource-managed TPM device; per-fd transient handles and built-in
/// cleanup, so no coordination with other TPM users is needed.
#[cfg(target_os = "linux")]
pub const LINUX_DEVICE: &str = "/dev/tpmrm0";

#[cfg(target_os = "linux")]
pub struct LinuxDevice {
    file: fs::File,
}

#[cfg(target_os = "linux")]
impl LinuxDevice {
    pub fn open() -> Result<Self> {
        Self::open_path(LINUX_DEVICE)
    }

    pub fn open_path(path: &str) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| {
                format!("failed to open TPM device `{path}` (is this user in the `tss` group?)")
            })?;
        Ok(Self { file })
    }
}

#[cfg(target_os = "linux")]
impl TpmTransport for LinuxDevice {
    fn transceive(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize> {
        self.file
            .write_all(command)
            .context("failed to write TPM command")?;
        // The character device returns the complete response in one read.
        let n = self
            .file
            .read(response)
            .context("failed to read TPM response")?;
        ensure!(n >= RESPONSE_HEADER_LEN, "short TPM response");
        Ok(n)
    }
}

const RESPONSE_HEADER_LEN: usize = 10;

/// Windows TBS (TPM Base Services) context. The OS service mediates all TPM
/// access, enforces its command allow-list, and owns dictionary-attack
/// lockout management.
#[cfg(windows)]
pub struct TbsContext {
    handle: *mut core::ffi::c_void,
}

// The TBS context handle is not thread-affine; TpmSealer serializes access
// through its Mutex.
#[cfg(windows)]
unsafe impl Send for TbsContext {}

#[cfg(windows)]
impl TbsContext {
    const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;
    const TBS_E_ACCESS_DENIED: u32 = 0x8028_4012;
    const TPM_E_COMMAND_BLOCKED: u32 = 0x8028_0400;

    pub fn open() -> Result<Self> {
        use windows_sys::Win32::System::TpmBaseServices::{
            TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0,
            TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS, Tbsi_Context_Create,
        };

        let params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            // Bitfield LSB-first: requestRaw, includeTpm12, includeTpm20.
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 0b100 },
        };
        let mut handle = core::ptr::null_mut();

        let rc = unsafe {
            Tbsi_Context_Create(
                (&params as *const TBS_CONTEXT_PARAMS2).cast::<TBS_CONTEXT_PARAMS>(),
                &mut handle,
            )
        };

        match rc {
            TBS_SUCCESS => Ok(Self { handle }),
            Self::TBS_E_TPM_NOT_FOUND => bail!("no TPM 2.0 present (TBS_E_TPM_NOT_FOUND)"),
            Self::TBS_E_ACCESS_DENIED => bail!("TBS denied access (TBS_E_ACCESS_DENIED)"),
            other => bail!("Tbsi_Context_Create failed: {other:#010x}"),
        }
    }
}

#[cfg(windows)]
impl Drop for TbsContext {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::TpmBaseServices::Tbsip_Context_Close(self.handle);
        }
    }
}

#[cfg(windows)]
impl TpmTransport for TbsContext {
    fn transceive(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize> {
        use windows_sys::Win32::System::TpmBaseServices::{
            TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_SUCCESS,
            Tbsip_Submit_Command,
        };

        // In/out: capacity on entry, actual response length on return.
        let mut len = u32::try_from(response.len()).context("response buffer too large")?;

        let rc = unsafe {
            Tbsip_Submit_Command(
                self.handle,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                response.as_mut_ptr(),
                &mut len,
            )
        };

        match rc {
            TBS_SUCCESS => {
                let n = len as usize;
                ensure!(n >= RESPONSE_HEADER_LEN, "short TBS response");
                Ok(n)
            }
            Self::TPM_E_COMMAND_BLOCKED => {
                bail!("TPM command blocked by Windows policy (TPM_E_COMMAND_BLOCKED)")
            }
            other => bail!("Tbsip_Submit_Command failed: {other:#010x}"),
        }
    }
}

/// swtpm's raw data channel (`swtpm socket --server type=tcp,...`): plain TPM
/// command/response frames over TCP. Start swtpm with
/// `--flags not-need-init,startup-clear` so no control-channel init is needed.
pub struct SwtpmSocket {
    stream: std::net::TcpStream,
}

impl SwtpmSocket {
    pub fn connect(addr: impl std::net::ToSocketAddrs) -> Result<Self> {
        let stream = std::net::TcpStream::connect(addr).context("failed to connect to swtpm")?;
        stream.set_nodelay(true).ok();
        let timeout = Some(std::time::Duration::from_secs(10));
        stream.set_read_timeout(timeout).ok();
        stream.set_write_timeout(timeout).ok();
        Ok(Self { stream })
    }
}

impl TpmTransport for SwtpmSocket {
    fn transceive(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize> {
        self.stream
            .write_all(command)
            .context("failed to write swtpm command")?;

        // TCP has no message boundaries: read the 10-byte header, then the
        // rest of the declared frame size.
        self.stream
            .read_exact(&mut response[..RESPONSE_HEADER_LEN])
            .context("failed to read swtpm response header")?;
        let size = u32::from_be_bytes(response[2..6].try_into().expect("4-byte slice")) as usize;
        ensure!(
            (RESPONSE_HEADER_LEN..=response.len()).contains(&size),
            "swtpm response size {size} out of range"
        );
        self.stream
            .read_exact(&mut response[RESPONSE_HEADER_LEN..size])
            .context("failed to read swtpm response body")?;

        Ok(size)
    }
}

/// TPM 2.0 [`HardwareSealer`]: wraps the hardware secret as a sealed-data
/// object under a fresh deterministic owner-hierarchy primary. Sealed to the
/// storage hierarchy, not PCRs. No parameter encryption: prefer fTPM/enclave
/// backends, where there is no bus to interpose.
pub struct TpmSealer<T: TpmTransport> {
    transport: Mutex<T>,
}

#[cfg(target_os = "linux")]
impl TpmSealer<LinuxDevice> {
    pub fn open() -> Result<Self> {
        Ok(Self::new(LinuxDevice::open()?))
    }
}

#[cfg(windows)]
impl TpmSealer<TbsContext> {
    pub fn open() -> Result<Self> {
        Ok(Self::new(TbsContext::open()?))
    }
}

impl<T: TpmTransport> TpmSealer<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport: Mutex::new(transport),
        }
    }

    fn with_session<R>(&self, f: impl FnOnce(&mut Session<'_, T>) -> Result<R>) -> Result<R> {
        let mut transport = self
            .transport
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut session = Session {
            transport: &mut *transport,
            tx: [0; TPM_MAX_COMMAND_SIZE],
            rx: [0; TPM_MAX_COMMAND_SIZE],
        };

        let result = f(&mut session);

        // Buffers carried the secret in cleartext.
        session.tx.zeroize();
        session.rx.zeroize();

        result
    }
}

impl<T: TpmTransport> HardwareSealer for TpmSealer<T> {
    fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>> {
        self.with_session(|session| {
            let primary = session.create_primary()?;
            let result = session.create_sealed(primary, secret);
            session.flush(primary);
            result
        })
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let body = blob
            .strip_prefix(BLOB_MAGIC)
            .ok_or_else(|| anyhow!("not a gilgamesh TPM2 blob"))?;

        let (private, rest) =
            <Tpm2bPrivate as TpmField>::cast_prefix_field(body).map_err(protocol_err)?;
        let (public, rest) =
            <Tpm2bPublic as TpmField>::cast_prefix_field(rest).map_err(protocol_err)?;
        ensure!(rest.is_empty(), "trailing bytes in TPM2 blob");

        let in_private = Tpm2bPrivate::try_from(private.data()).map_err(protocol_err)?;
        let in_public = owned_public(public)?;

        self.with_session(|session| {
            let primary = session.create_primary()?;
            let result = (|| {
                let object = session.load(primary, in_private, in_public)?;
                let result = session.unseal(object);
                session.flush(object);
                result
            })();
            session.flush(primary);
            result
        })
    }

    fn describe(&self) -> String {
        self.with_session(|session| session.manufacturer())
            .map(|manufacturer| format!("TPM 2.0 ({manufacturer})"))
            .unwrap_or_else(|err| format!("TPM 2.0 (unavailable: {err:#})"))
    }
}

struct Session<'a, T: TpmTransport> {
    transport: &'a mut T,
    tx: [u8; TPM_MAX_COMMAND_SIZE],
    rx: [u8; TPM_MAX_COMMAND_SIZE],
}

impl<T: TpmTransport> Session<'_, T> {
    fn execute(
        &mut self,
        command: &impl TpmFrame,
        tag: TpmSt,
        sessions: &[TpmsAuthCommand],
        cc: TpmCc,
    ) -> Result<&TpmResponse> {
        let len = {
            let mut writer = TpmWriter::new(&mut self.tx);
            tpm_marshal_command(command, tag, sessions, &mut writer).map_err(protocol_err)?;
            writer.len()
        };

        let n = self.transport.transceive(&self.tx[..len], &mut self.rx)?;

        match TpmResponseView::cast_frame(cc, &self.rx[..n]).map_err(protocol_err)? {
            TpmResponseOutcome::Dispatched(view) => Ok(view.response()),
            TpmResponseOutcome::Rejected(rc) => Err(anyhow!("TPM rejected {cc}: {rc}")),
        }
    }

    /// Create the deterministic storage primary (SRK-style ECC P-256 under
    /// TPM_RH_OWNER with empty auth). The same template always regenerates the
    /// same key from the TPM's hierarchy seed, so nothing about it needs to be
    /// persisted.
    fn create_primary(&mut self) -> Result<u32> {
        let command = TpmCreatePrimaryCommand {
            handles: [TpmHandle::new(TpmRh::Owner.value())],
            in_sensitive: Tpm2bSensitiveCreate::from(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::new(),
                data: Tpm2bSensitiveData::new(),
            }),
            in_public: Tpm2bPublic::from(storage_primary_template()),
            outside_info: Tpm2bData::new(),
            creation_pcr: TpmlPcrSelection::new(),
        };

        let response = self
            .execute(
                &command,
                TpmSt::Sessions,
                &[password_session(&[])?],
                TpmCc::CreatePrimary,
            )
            .context("CreatePrimary failed (does the owner hierarchy have an auth value set?)")?;

        let (handles, _, _) = split_sessions_response(response, 1)?;
        let (handle, _) = TpmHandle::cast_prefix(handles).map_err(protocol_err)?;

        Ok(handle.value())
    }

    fn create_sealed(&mut self, parent: u32, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let command = TpmCreateCommand {
            handles: [TpmHandle::new(parent)],
            in_sensitive: Tpm2bSensitiveCreate::from(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::new(),
                data: Tpm2bSensitiveData::try_from(&secret[..]).map_err(protocol_err)?,
            }),
            in_public: Tpm2bPublic::from(sealed_data_template()),
            outside_info: Tpm2bData::new(),
            creation_pcr: TpmlPcrSelection::new(),
        };

        let response = self.execute(
            &command,
            TpmSt::Sessions,
            &[password_session(&[])?],
            TpmCc::Create,
        )?;

        let (_, parameters, _) = split_sessions_response(response, 0)?;
        let (private, rest) =
            <Tpm2bPrivate as TpmField>::cast_prefix_field(parameters).map_err(protocol_err)?;
        let (public, _) =
            <Tpm2bPublic as TpmField>::cast_prefix_field(rest).map_err(protocol_err)?;

        let mut blob = BLOB_MAGIC.to_vec();
        blob.extend_from_slice(private.as_bytes());
        blob.extend_from_slice(public.as_bytes());

        Ok(blob)
    }

    fn load(
        &mut self,
        parent: u32,
        in_private: Tpm2bPrivate,
        in_public: Tpm2bPublic,
    ) -> Result<u32> {
        let command = TpmLoadCommand {
            handles: [TpmHandle::new(parent)],
            in_private,
            in_public,
        };

        let response = self.execute(
            &command,
            TpmSt::Sessions,
            &[password_session(&[])?],
            TpmCc::Load,
        )?;

        let (handles, _, _) = split_sessions_response(response, 1)?;
        let (handle, _) = TpmHandle::cast_prefix(handles).map_err(protocol_err)?;

        Ok(handle.value())
    }

    fn unseal(&mut self, object: u32) -> Result<Zeroizing<[u8; 32]>> {
        let command = TpmUnsealCommand {
            handles: [TpmHandle::new(object)],
        };

        let response = self.execute(
            &command,
            TpmSt::Sessions,
            &[password_session(&[])?],
            TpmCc::Unseal,
        )?;

        let (_, parameters, _) = split_sessions_response(response, 0)?;
        let (data, _) = <Tpm2bSensitiveData as TpmField>::cast_prefix_field(parameters)
            .map_err(protocol_err)?;

        let mut secret = Zeroizing::new([0; 32]);
        ensure!(
            data.data().len() == secret.len(),
            "TPM unsealed {} bytes, expected 32",
            data.data().len()
        );
        secret.copy_from_slice(data.data());

        Ok(secret)
    }

    /// Best-effort: the kernel resource manager flushes transients on fd close
    /// anyway, so a flush failure is not worth failing the operation over.
    fn flush(&mut self, handle: u32) {
        let command = TpmFlushContextCommand {
            handles: [],
            flush_handle: TpmHandle::new(handle),
        };
        let _ = self.execute(&command, TpmSt::NoSessions, &[], TpmCc::FlushContext);
    }

    fn manufacturer(&mut self) -> Result<String> {
        let command = TpmGetCapabilityCommand {
            handles: [],
            cap: TpmCap::TpmProperties,
            property: TpmUint32::new(TpmPt::Manufacturer.value()),
            property_count: TpmUint32::new(1),
        };

        let response = self.execute(&command, TpmSt::NoSessions, &[], TpmCc::GetCapability)?;

        // NO_SESSIONS response: no parameterSize field, no auth area.
        let body = response.body();
        let (_more, rest) =
            <TpmiYesNo as TpmField>::cast_prefix_field(body).map_err(protocol_err)?;
        let (cap, rest) = <TpmCap as TpmField>::cast_prefix_field(rest).map_err(protocol_err)?;
        let (capabilities, _) = TpmuCapabilities::cast_tagged(cap, rest).map_err(protocol_err)?;

        let TpmuCapabilitiesView::TpmProperties(properties) = capabilities else {
            bail!("TPM returned unexpected capability data");
        };

        // Parse raw u32 pairs: going through TpmPt rejects vendor properties.
        let mut items = properties.items_bytes();
        for _ in 0..properties.count() {
            let (property, rest) = TpmUint32::cast_prefix(items).map_err(protocol_err)?;
            let (value, rest) = TpmUint32::cast_prefix(rest).map_err(protocol_err)?;
            items = rest;

            if property.value() == TpmPt::Manufacturer.value() {
                let ascii = value.value().to_be_bytes();
                if ascii
                    .iter()
                    .all(|byte| byte.is_ascii_graphic() || *byte == 0)
                {
                    return Ok(String::from_utf8_lossy(&ascii)
                        .trim_end_matches('\0')
                        .to_string());
                }
                return Ok(format!("{:08x}", value.value()));
            }
        }

        bail!("TPM did not report a manufacturer")
    }
}

fn protocol_err(err: tpm2_protocol::TpmError) -> Error {
    anyhow!("TPM protocol error: {err:?}")
}

fn password_session(auth: &[u8]) -> Result<TpmsAuthCommand> {
    Ok(TpmsAuthCommand {
        session_handle: TpmHandle::new(TpmRh::Pw.value()),
        nonce: Tpm2bNonce::new(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(auth).map_err(protocol_err)?,
    })
}

/// Split a TPM_ST_SESSIONS response body into (handles, parameters, auth).
fn split_sessions_response(
    response: &TpmResponse,
    handle_count: usize,
) -> Result<(&[u8], &[u8], &[u8])> {
    let body = response.body();
    ensure!(
        body.len() >= handle_count * 4,
        "TPM response handle area truncated"
    );
    let (handles, rest) = body.split_at(handle_count * 4);

    let (size, rest) = TpmUint32::cast_prefix(rest).map_err(protocol_err)?;
    let size = size.value() as usize;
    ensure!(rest.len() >= size, "TPM response parameter area truncated");
    let (parameters, auth) = rest.split_at(size);

    Ok((handles, parameters, auth))
}

/// ECC P-256 restricted-decrypt storage primary (standard SRK-style template).
/// Frozen: a changed template is a different primary, orphaning every blob.
fn storage_primary_template() -> TpmtPublic {
    TpmtPublic {
        object_type: TpmAlgId::Ecc,
        name_alg: TpmAlgId::Sha256,
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::new(),
        parameters: TpmuPublicParms::Ecc(TpmsEccParms {
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Aes,
                key_bits: TpmuSymKeyBits::Aes(TpmUint16::new(128)),
                mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
            },
            scheme: TpmtEccScheme {
                scheme: TpmAlgId::Null,
                details: TpmuAsymScheme::Null,
            },
            curve_id: TpmEccCurve::NistP256,
            kdf: TpmtKdfScheme {
                scheme: TpmAlgId::Null,
                details: TpmuKdfScheme::Null,
            },
        }),
        unique: TpmuPublicId::Ecc(TpmsEccPoint::default()),
    }
}

/// KEYEDHASH sealed-data template: we supply the data (no
/// SENSITIVE_DATA_ORIGIN), scheme Null, no policy, empty auth — the unlock
/// password already gates the KEK via AND-composition.
fn sealed_data_template() -> TpmtPublic {
    TpmtPublic {
        object_type: TpmAlgId::KeyedHash,
        name_alg: TpmAlgId::Sha256,
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::new(),
        parameters: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
            scheme: TpmtKeyedhashScheme {
                scheme: TpmAlgId::Null,
                details: TpmuKeyedhashScheme::Null,
            },
        }),
        unique: TpmuPublicId::KeyedHash(Tpm2bDigest::new()),
    }
}

/// Rebuild an owned public area for Load from the blob's wire form. The crate
/// has no unmarshal-to-owned, so reconstruct from the known template plus the
/// TPM-computed unique digest (the Name depends on it).
fn owned_public(wire: &Tpm2bPublicWire) -> Result<Tpm2bPublic> {
    let view = wire.inner().map_err(protocol_err)?;
    ensure!(
        view.object_type == TpmAlgId::KeyedHash,
        "TPM2 blob public area is not a sealed keyedhash object"
    );

    let TpmuPublicIdView::KeyedHash(unique) = view.unique else {
        bail!("TPM2 blob public area has mismatched unique field");
    };

    let mut public = sealed_data_template();
    public.object_attributes = view.object_attributes;
    public.unique =
        TpmuPublicId::KeyedHash(Tpm2bDigest::try_from(unique.data()).map_err(protocol_err)?);

    Ok(Tpm2bPublic::from(public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_blobs_are_rejected_without_touching_hardware() {
        struct Unreachable;
        impl TpmTransport for Unreachable {
            fn transceive(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize> {
                panic!("transport must not be reached for malformed blobs");
            }
        }

        let sealer = TpmSealer::new(Unreachable);
        assert!(sealer.unseal(b"garbage").is_err());
        assert!(sealer.unseal(BLOB_MAGIC).is_err());
    }

    #[test]
    fn command_frames_pass_the_protocol_validator() {
        fn check(command: &impl TpmFrame, tag: TpmSt, sessions: &[TpmsAuthCommand]) {
            let mut buf = [0; TPM_MAX_COMMAND_SIZE];
            let len = {
                let mut writer = TpmWriter::new(&mut buf);
                tpm_marshal_command(command, tag, sessions, &mut writer).unwrap();
                writer.len()
            };
            // The crate's own frame parser re-validates handle counts, auth
            // areas, and dispatch — catches marshaling bugs without hardware.
            tpm2_protocol::frame::TpmCommandView::cast_frame(&buf[..len]).unwrap();
        }

        let sessions = [password_session(&[]).unwrap()];

        check(
            &TpmCreatePrimaryCommand {
                handles: [TpmHandle::new(TpmRh::Owner.value())],
                in_sensitive: Tpm2bSensitiveCreate::from(TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::new(),
                    data: Tpm2bSensitiveData::new(),
                }),
                in_public: Tpm2bPublic::from(storage_primary_template()),
                outside_info: Tpm2bData::new(),
                creation_pcr: TpmlPcrSelection::new(),
            },
            TpmSt::Sessions,
            &sessions,
        );

        check(
            &TpmCreateCommand {
                handles: [TpmHandle::new(0x8000_0000)],
                in_sensitive: Tpm2bSensitiveCreate::from(TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::new(),
                    data: Tpm2bSensitiveData::try_from(&[0x42; 32][..]).unwrap(),
                }),
                in_public: Tpm2bPublic::from(sealed_data_template()),
                outside_info: Tpm2bData::new(),
                creation_pcr: TpmlPcrSelection::new(),
            },
            TpmSt::Sessions,
            &sessions,
        );

        check(
            &TpmLoadCommand {
                handles: [TpmHandle::new(0x8000_0000)],
                in_private: Tpm2bPrivate::try_from(&[0; 42][..]).unwrap(),
                in_public: Tpm2bPublic::from(sealed_data_template()),
            },
            TpmSt::Sessions,
            &sessions,
        );

        check(
            &TpmUnsealCommand {
                handles: [TpmHandle::new(0x8000_0001)],
            },
            TpmSt::Sessions,
            &sessions,
        );

        check(
            &TpmFlushContextCommand {
                handles: [],
                flush_handle: TpmHandle::new(0x8000_0000),
            },
            TpmSt::NoSessions,
            &[],
        );

        check(
            &TpmGetCapabilityCommand {
                handles: [],
                cap: TpmCap::TpmProperties,
                property: TpmUint32::new(TpmPt::Manufacturer.value()),
                property_count: TpmUint32::new(1),
            },
            TpmSt::NoSessions,
            &[],
        );
    }

    fn roundtrip(sealer: &impl HardwareSealer) {
        println!("backend: {}", sealer.describe());

        let secret = [0x42; 32];
        let blob = sealer.seal(&secret).unwrap();
        assert_eq!(*sealer.unseal(&blob).unwrap(), secret);

        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(sealer.unseal(&tampered).is_err());
    }

    struct Swtpm {
        child: std::process::Child,
        port: u16,
    }

    impl Swtpm {
        /// Spawn a fresh software TPM, or `None` if swtpm is not installed.
        fn spawn(dir: &std::path::Path) -> Option<Self> {
            let port = {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.local_addr().unwrap().port()
            };

            let child = std::process::Command::new("swtpm")
                .args([
                    "socket",
                    "--tpm2",
                    "--server",
                    &format!("type=tcp,port={port},bindaddr=127.0.0.1"),
                    "--ctrl",
                    &format!("type=unixio,path={}", dir.join("ctrl.sock").display()),
                    "--tpmstate",
                    &format!("dir={}", dir.display()),
                    "--flags",
                    "not-need-init,startup-clear",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok()?;

            Some(Self { child, port })
        }

        fn connect(&self) -> Result<SwtpmSocket> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match SwtpmSocket::connect(("127.0.0.1", self.port)) {
                    Ok(socket) => return Ok(socket),
                    Err(err) if std::time::Instant::now() > deadline => return Err(err),
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
                }
            }
        }
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            // Reap only if the signal landed; in sandboxes that deny kill(),
            // waiting would hang forever on a child that never exits.
            if self.child.kill().is_ok() {
                let _ = self.child.wait();
            }
        }
    }

    #[test]
    fn swtpm_seal_unseal_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let Some(swtpm) = Swtpm::spawn(dir.path()) else {
            eprintln!("skipping: swtpm is not installed");
            return;
        };

        roundtrip(&TpmSealer::new(swtpm.connect().unwrap()));
    }

    #[test]
    fn swtpm_blobs_do_not_unseal_on_a_different_tpm() {
        let dir_a = tempfile::TempDir::new().unwrap();
        let dir_b = tempfile::TempDir::new().unwrap();
        let (Some(swtpm_a), Some(swtpm_b)) =
            (Swtpm::spawn(dir_a.path()), Swtpm::spawn(dir_b.path()))
        else {
            eprintln!("skipping: swtpm is not installed");
            return;
        };

        let blob = TpmSealer::new(swtpm_a.connect().unwrap())
            .seal(&[0x42; 32])
            .unwrap();

        // A different TPM has a different hierarchy seed: the blob must be
        // machine-bound, not merely encrypted.
        assert!(
            TpmSealer::new(swtpm_b.connect().unwrap())
                .unseal(&blob)
                .is_err()
        );
    }

    #[test]
    #[ignore = "requires /dev/tpmrm0 access (add this user to the `tss` group)"]
    #[cfg(target_os = "linux")]
    fn real_tpm_seal_unseal_roundtrip() {
        roundtrip(&TpmSealer::open().unwrap());
    }
}
