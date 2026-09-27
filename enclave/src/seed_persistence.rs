//! Persistent seed lifecycle. The parent holds only an opaque KMS ciphertext;
//! KMS responses are authenticated and decrypted inside the enclave.

use std::io;
#[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::Network;
use prost::{bytes::Bytes, Message};
use zeroize::Zeroizing;

use crate::conn::{remaining_until, DeadlineStream};
use crate::error::{CustodyFailure, EnclaveError, Result};
use crate::framing;
use crate::keys::KeyManager;
use crate::kms::{AwsCredentials, CustodyFlow, KmsClient, KmsConfig, MAX_CIPHERTEXT_BYTES};
use crate::proto::{
    seed_storage_request::Request, seed_storage_response::Response, SeedCreateRequest,
    SeedCredentialsRequest, SeedLoadRequest, SeedStorageErrorCode, SeedStorageRequest,
    SeedStorageResponse,
};

/// Upper bound on one framed broker message in either direction.
pub(crate) const MAX_MESSAGE_BYTES: usize = 64 * 1024;

// TCP is only used by non-VSOCK development builds and unit fixtures.
#[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
type BrokerStream = TcpStream;
#[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
type BrokerStream = vsock::VsockStream;

pub const BROKER_LOCAL_PORT: u16 = 3446;
pub const BROKER_VSOCK_PORT: u32 = 8004;
// Leave room inside the 30-second parent/request timeout for ingress and reply.
pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(25);
pub(crate) const RESPONSE_RESERVE: Duration = Duration::from_secs(2);
// The broker's own seven-second operation deadline expires before this cap.
const BROKER_TIMEOUT: Duration = Duration::from_secs(8);

fn failure(message: &str) -> EnclaveError {
    EnclaveError::InvalidRequest(format!("seed persistence: {message}"))
}

/// Production installs a persistent source at boot. Tests can inject a source
/// without teaching the production wire protocol to accept plaintext seeds.
pub trait SeedSource: Send + Sync {
    /// Bound every external operation by this same absolute deadline. The state
    /// machine also checks it immediately before activating the returned keys.
    fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager>;
}

trait SeedStore {
    fn load(&self, deadline: Instant) -> Result<Option<Vec<u8>>>;
    /// Atomically create if absent, then return the persisted winning blob.
    fn create(&self, ciphertext: &[u8], deadline: Instant) -> Result<Vec<u8>>;
}

trait SeedKms {
    fn generate(&self, deadline: Instant) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], deadline: Instant) -> Result<Zeroizing<[u8; 64]>>;
}

impl SeedKms for KmsClient {
    fn generate(&self, deadline: Instant) -> Result<Vec<u8>> {
        self.generate_ciphertext(deadline)
    }

    fn decrypt(&self, ciphertext: &[u8], deadline: Instant) -> Result<Zeroizing<[u8; 64]>> {
        self.decrypt_seed(ciphertext, deadline)
    }
}

fn recover_seed(
    store: &impl SeedStore,
    kms: &impl SeedKms,
    expected_evm_address: Option<[u8; 20]>,
    deadline: Instant,
) -> Result<Zeroizing<[u8; 64]>> {
    remaining_until(deadline)?;
    // Only an explicit missing-object response permits first-use creation.
    // An expected identity makes missing ciphertext a recovery failure, so
    // neither KMS generation nor persistence can replace a lost pinned seed.
    let ciphertext = match store.load(deadline)? {
        Some(blob) => {
            tracing::info!("seed custody: loading saved identity");
            blob
        }
        None if expected_evm_address.is_none() => {
            tracing::info!("seed custody: no saved object; attempting conditional creation");
            remaining_until(deadline)?;
            let blob = kms.generate(deadline)?;
            validate_ciphertext(&blob)?;
            remaining_until(deadline)?;
            store.create(&blob, deadline)?
        }
        None => {
            return Err(failure(
                "saved seed is missing; a pinned identity cannot be replaced",
            ))
        }
    };
    validate_ciphertext(&ciphertext)?;
    // This is the only step that returns plaintext to Rust: recover the blob
    // returned by persistence, including the winner of concurrent bootstrap.
    remaining_until(deadline)?;
    let seed = kms.decrypt(&ciphertext, deadline)?;
    remaining_until(deadline)?;
    Ok(seed)
}

fn validate_ciphertext(blob: &[u8]) -> Result<()> {
    if blob.is_empty() || blob.len() > MAX_CIPHERTEXT_BYTES {
        return Err(failure("invalid ciphertext length"));
    }
    Ok(())
}

pub struct PersistentSeed {
    config: KmsConfig,
    broker: SeedBroker,
    expected_evm_address: Option<[u8; 20]>,
}

impl PersistentSeed {
    /// These nonsecret values belong in the measured EIF configuration.
    pub fn from_env(flow: CustodyFlow) -> Result<Self> {
        let config = KmsConfig::from_env(flow)?;
        let expected_evm_address = match std::env::var("KMS_EXPECTED_EVM_ADDRESS") {
            Err(std::env::VarError::NotPresent) => None,
            Ok(value) if value.is_empty() => None,
            Ok(value) => Some(
                hex::decode(value.strip_prefix("0x").unwrap_or(&value))
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| failure("KMS_EXPECTED_EVM_ADDRESS must be 20-byte hex"))?,
            ),
            Err(_) => return Err(failure("invalid expected address configuration")),
        };
        let broker = SeedBroker {
            #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, BROKER_LOCAL_PORT)),
            seed_id: config.seed_id.clone(),
        };
        Ok(Self {
            config,
            broker,
            expected_evm_address,
        })
    }
}

impl SeedSource for PersistentSeed {
    fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager> {
        // Refresh short-lived instance-role credentials on every attempt.
        let credentials = self.broker.credentials(deadline)?;
        let kms = KmsClient::new(self.config.clone(), credentials, network)?;
        let seed = recover_seed(&self.broker, &kms, self.expected_evm_address, deadline)?;
        restore_keys(seed, network, self.expected_evm_address)
    }
}

fn restore_keys(
    seed: Zeroizing<[u8; 64]>,
    network: Network,
    expected: Option<[u8; 20]>,
) -> Result<KeyManager> {
    let manager = KeyManager::from_seed(*seed, network)?;
    if expected.is_some_and(|address| *manager.evm_address() != address) {
        return Err(EnclaveError::IdentityMismatch);
    }
    Ok(manager)
}

struct SeedBroker {
    #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
    address: SocketAddr,
    seed_id: String,
}

impl SeedBroker {
    fn connect(&self, deadline: Instant) -> io::Result<BrokerStream> {
        #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
        {
            connect_vsock(BROKER_VSOCK_PORT, deadline)
        }
        #[cfg(not(all(feature = "vsock", target_os = "linux", not(test))))]
        {
            TcpStream::connect_timeout(&self.address, remaining_until(deadline)?)
        }
    }

    fn request(&self, request: Request, deadline: Instant) -> Result<Response> {
        let deadline = deadline.min(Instant::now() + BROKER_TIMEOUT);
        remaining_until(deadline)
            .map_err(|_| broker_error(SeedStorageErrorCode::OperationTimeout))?;
        let stream = self
            .connect(deadline)
            .map_err(|_| broker_error(SeedStorageErrorCode::AwsUnavailable))?;
        let mut stream = DeadlineStream::with_deadline(stream, deadline, BROKER_TIMEOUT);
        let request = SeedStorageRequest {
            request: Some(request),
        };
        if request.encoded_len() > MAX_MESSAGE_BYTES {
            return Err(failure("broker request too large"));
        }
        framing::write_message(&mut stream, &request)
            .map_err(|_| broker_error(SeedStorageErrorCode::AwsUnavailable))?;
        let bytes = framing::read_frame(&mut stream, MAX_MESSAGE_BYTES as u32).map_err(
            |error| match error {
                EnclaveError::Io(_) => broker_error(SeedStorageErrorCode::AwsUnavailable),
                _ => broker_error(SeedStorageErrorCode::InvalidFrame),
            },
        )?;
        // Decode from owned Bytes, not a slice: credential fields then share
        // this zeroizing allocation, even on partial decode or replacement.
        // Never log the response or the protobuf decoder's untrusted details.
        let response = SeedStorageResponse::decode(Bytes::from_owner(bytes))
            .map_err(|_| broker_error(SeedStorageErrorCode::InvalidFrame))?;
        match response.response {
            Some(Response::Error(error)) => Err(broker_error(
                SeedStorageErrorCode::try_from(error.code)
                    .unwrap_or(SeedStorageErrorCode::Unspecified),
            )),
            Some(response) => Ok(response),
            None => Err(broker_error(SeedStorageErrorCode::InvalidFrame)),
        }
    }

    fn credentials(&self, deadline: Instant) -> Result<AwsCredentials> {
        let Response::Credentials(credentials) =
            self.request(Request::Credentials(SeedCredentialsRequest {}), deadline)?
        else {
            return Err(broker_error(SeedStorageErrorCode::InvalidFrame));
        };
        fn secret(bytes: &[u8], max: usize) -> Result<Zeroizing<String>> {
            if bytes.len() > max {
                return Err(broker_error(SeedStorageErrorCode::InvalidFrame));
            }
            let text = std::str::from_utf8(bytes)
                .map_err(|_| broker_error(SeedStorageErrorCode::InvalidFrame))?;
            Ok(Zeroizing::new(text.to_owned()))
        }
        AwsCredentials::from_protected(
            secret(&credentials.access_key_id, 128)?,
            secret(&credentials.secret_access_key, 256)?,
            secret(&credentials.session_token, 16 * 1024)?,
        )
    }
}

fn broker_error(code: SeedStorageErrorCode) -> EnclaveError {
    use SeedStorageErrorCode::*;
    let failure = match code {
        Configuration | SeedIdNotAllowed => CustodyFailure::Configuration,
        AccessDenied => CustodyFailure::AccessDenied,
        AwsUnavailable | Busy | OperationTimeout | RequestTimeout => CustodyFailure::Unavailable,
        InvalidCiphertext => CustodyFailure::InvalidCiphertext,
        Internal => CustodyFailure::Internal,
        _ => CustodyFailure::InvalidResponse,
    };
    EnclaveError::Custody {
        service: "seed broker",
        failure,
    }
}

impl SeedStore for SeedBroker {
    fn load(&self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        match self.request(
            Request::Load(SeedLoadRequest {
                seed_id: self.seed_id.clone(),
            }),
            deadline,
        )? {
            Response::Ciphertext(blob) => {
                validate_ciphertext(&blob.ciphertext)?;
                Ok(Some(blob.ciphertext))
            }
            // No missing/default field or error may authorize generation.
            Response::NotFound(_) => Ok(None),
            _ => Err(broker_error(SeedStorageErrorCode::InvalidFrame)),
        }
    }

    fn create(&self, ciphertext: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        validate_ciphertext(ciphertext)?;
        match self.request(
            Request::Create(SeedCreateRequest {
                seed_id: self.seed_id.clone(),
                ciphertext: ciphertext.to_vec(),
            }),
            deadline,
        )? {
            Response::Ciphertext(blob) => {
                validate_ciphertext(&blob.ciphertext)?;
                Ok(blob.ciphertext)
            }
            _ => Err(failure("broker did not return a committed seed")),
        }
    }
}

// The only broker connection is owned by the initialization attempt: there is
// no background relay or detached I/O. Parent CID 3 is fixed by Nitro, and the
// nonblocking connect consumes the same deadline as framing and recovery.
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn connect_vsock(port: u32, deadline: Instant) -> io::Result<vsock::VsockStream> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::os::fd::{AsFd, AsRawFd};
    remaining_until(deadline)?;
    let socket = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    remaining_until(deadline)?;
    match connect(socket.as_raw_fd(), &VsockAddr::new(3, port)) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => loop {
            let millis = remaining_until(deadline)?
                .as_millis()
                .clamp(1, i32::MAX as u128);
            let timeout = PollTimeout::try_from(millis).map_err(io::Error::other)?;
            let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLOUT)];
            let ready = match poll(&mut fds, timeout) {
                Ok(ready) => ready,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
            };
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "vsock connect timed out",
                ));
            }
            let error =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::SocketError)?;
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            if !fds[0]
                .revents()
                .is_some_and(|events| events.contains(PollFlags::POLLOUT))
            {
                return Err(io::Error::other("vsock connect did not complete"));
            }
            break;
        },
        Err(error) => return Err(error.into()),
    }
    remaining_until(deadline)?;
    let stream = vsock::VsockStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{SeedCiphertext, SeedCredentials, SeedNotFound, SeedStorageError};
    use std::cell::{Cell, RefCell};
    use std::io::Write;

    #[derive(Default)]
    struct Store {
        saved: RefCell<Option<Vec<u8>>>,
        creates: Cell<u32>,
        fail_read: Cell<bool>,
        fail_write: Cell<bool>,
        race_winner: Option<Vec<u8>>,
    }
    impl SeedStore for Store {
        fn load(&self, _deadline: Instant) -> Result<Option<Vec<u8>>> {
            if self.fail_read.get() {
                return Err(failure("read failed"));
            }
            Ok(self.saved.borrow().clone())
        }
        fn create(&self, blob: &[u8], _deadline: Instant) -> Result<Vec<u8>> {
            self.creates.set(self.creates.get() + 1);
            if self.fail_write.get() {
                return Err(failure("write failed"));
            }
            let mut saved = self.saved.borrow_mut();
            let winner = saved
                .get_or_insert_with(|| self.race_winner.clone().unwrap_or_else(|| blob.to_vec()));
            Ok(winner.clone())
        }
    }
    #[derive(Default)]
    struct Kms {
        generates: Cell<u32>,
        decrypts: Cell<u32>,
        fail_decrypt: bool,
    }
    impl SeedKms for Kms {
        fn generate(&self, _deadline: Instant) -> Result<Vec<u8>> {
            self.generates.set(self.generates.get() + 1);
            Ok(vec![42; 64]) // Opaque ciphertext stand-in; never a production backend.
        }
        fn decrypt(&self, blob: &[u8], _deadline: Instant) -> Result<Zeroizing<[u8; 64]>> {
            self.decrypts.set(self.decrypts.get() + 1);
            if self.fail_decrypt {
                return Err(failure("KMS denied"));
            }
            Ok(Zeroizing::new(
                blob.try_into().map_err(|_| failure("bad ciphertext"))?,
            ))
        }
    }

    #[test]
    fn valid_ciphertext_for_a_different_identity_is_rejected() {
        let expected = *KeyManager::from_seed([42; 64], Network::Bitcoin)
            .unwrap()
            .evm_address();
        assert!(restore_keys(Zeroizing::new([42; 64]), Network::Bitcoin, Some(expected)).is_ok());
        assert!(matches!(
            restore_keys(Zeroizing::new([17; 64]), Network::Bitcoin, Some(expected)),
            Err(EnclaveError::IdentityMismatch)
        ));
    }

    #[test]
    fn bootstrap_then_restart_and_replica_preserve_keys_and_signatures() {
        let store = Store::default();
        let kms = Kms::default();
        let first = recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).unwrap();
        let a = KeyManager::from_seed(*first, Network::Bitcoin).unwrap();
        let restored = recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).unwrap();
        let replica = recover_seed(
            &store,
            &kms,
            Some(*a.evm_address()),
            Instant::now() + RECOVERY_TIMEOUT,
        )
        .unwrap();
        assert_eq!(*first, *restored);
        assert_eq!(*first, *replica);
        assert_eq!(kms.generates.get(), 1);
        assert_eq!(store.creates.get(), 1);
        let b = KeyManager::from_seed(*restored, Network::Bitcoin).unwrap();
        assert_eq!(a.evm_address(), b.evm_address());
        assert_eq!(a.account_xpub_colored(), b.account_xpub_colored());
        assert_eq!(a.sign_evm(&[7; 32]).unwrap(), b.sign_evm(&[7; 32]).unwrap());
    }

    #[test]
    fn pinned_missing_seed_and_unreadable_store_never_generate_or_write() {
        let store = Store::default();
        let kms = Kms::default();
        assert!(recover_seed(
            &store,
            &kms,
            Some([1; 20]),
            Instant::now() + RECOVERY_TIMEOUT
        )
        .is_err());
        store.fail_read.set(true);
        assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
        assert_eq!(kms.generates.get(), 0);
        assert_eq!(kms.decrypts.get(), 0);
        assert_eq!(store.creates.get(), 0);
        assert!(store.saved.borrow().is_none());
    }

    #[test]
    fn existing_ciphertext_is_reused_with_or_without_a_pin() {
        let original = vec![42; 64];
        let store = Store {
            saved: RefCell::new(Some(original.clone())),
            ..Store::default()
        };
        let kms = Kms::default();
        let expected = *KeyManager::from_seed([42; 64], Network::Bitcoin)
            .unwrap()
            .evm_address();
        for pin in [None, Some(expected), Some([1; 20])] {
            let seed = recover_seed(&store, &kms, pin, Instant::now() + RECOVERY_TIMEOUT).unwrap();
            let keys = restore_keys(seed, Network::Bitcoin, pin);
            if pin == Some([1; 20]) {
                assert!(matches!(keys, Err(EnclaveError::IdentityMismatch)));
            } else {
                assert_eq!(*keys.unwrap().evm_address(), expected);
            }
        }
        assert_eq!(kms.generates.get(), 0);
        assert_eq!(kms.decrypts.get(), 3);
        assert_eq!(store.creates.get(), 0);
        assert_eq!(*store.saved.borrow(), Some(original));
    }

    #[test]
    fn failed_persistence_never_recovers_or_activates_generated_key() {
        let store = Store {
            fail_write: Cell::new(true),
            ..Store::default()
        };
        let kms = Kms::default();
        assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
        assert_eq!(kms.decrypts.get(), 0);
        assert!(store.saved.borrow().is_none());
    }

    #[test]
    fn concurrent_bootstrap_recovers_the_committed_winner() {
        let store = Store {
            race_winner: Some(vec![17; 64]),
            ..Store::default()
        };
        let seed = recover_seed(
            &store,
            &Kms::default(),
            None,
            Instant::now() + RECOVERY_TIMEOUT,
        )
        .unwrap();
        assert_eq!(*seed, [17; 64]);
    }

    #[test]
    fn kms_denial_and_corruption_do_not_replace_saved_seed() {
        let store = Store {
            saved: RefCell::new(Some(vec![99; 64])),
            ..Store::default()
        };
        let kms = Kms {
            fail_decrypt: true,
            ..Kms::default()
        };
        assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
        assert_eq!(kms.generates.get(), 0);
        *store.saved.borrow_mut() = Some(vec![]);
        assert!(recover_seed(&store, &kms, None, Instant::now() + RECOVERY_TIMEOUT).is_err());
        assert_eq!(kms.decrypts.get(), 1);
    }

    fn mock_broker(
        reply: impl FnOnce(TcpStream) + Send + 'static,
    ) -> (SeedBroker, std::thread::JoinHandle<SeedStorageRequest>) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let broker = SeedBroker {
            address: listener.local_addr().unwrap(),
            seed_id: "pool-1".into(),
        };
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = framing::read_message(&mut stream).unwrap();
            reply(stream);
            request
        });
        (broker, server)
    }

    fn frame(response: Response) -> Vec<u8> {
        let mut bytes = Vec::new();
        framing::write_message(
            &mut bytes,
            &SeedStorageResponse {
                response: Some(response),
            },
        )
        .unwrap();
        bytes
    }

    fn ciphertext(blob: Vec<u8>) -> Response {
        Response::Ciphertext(SeedCiphertext { ciphertext: blob })
    }

    fn credentials() -> Response {
        Response::Credentials(SeedCredentials {
            access_key_id: Bytes::from_static(b"AKID"),
            secret_access_key: Bytes::from_static(b"secret"),
            session_token: Bytes::from_static(b"token"),
        })
    }

    #[test]
    fn broker_socket_protocol_supports_fragmented_frames_for_all_operations() {
        let reply = frame(ciphertext(vec![17; 64]));
        let (broker, server) = mock_broker(move |mut stream| {
            for chunk in reply.chunks(3) {
                stream.write_all(chunk).unwrap();
            }
        });
        assert_eq!(
            broker
                .load(Instant::now() + Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            vec![17; 64]
        );
        assert_eq!(
            server.join().unwrap().request,
            Some(Request::Load(SeedLoadRequest {
                seed_id: "pool-1".into()
            }))
        );
        let (broker, server) = mock_broker(|mut stream| {
            stream.write_all(&frame(ciphertext(vec![99; 64]))).unwrap();
        });
        assert_eq!(
            broker
                .create(&[17; 64], Instant::now() + Duration::from_secs(2))
                .unwrap(),
            vec![99; 64]
        );
        assert_eq!(
            server.join().unwrap().request,
            Some(Request::Create(SeedCreateRequest {
                seed_id: "pool-1".into(),
                ciphertext: vec![17; 64]
            }))
        );
        let (broker, server) = mock_broker(|mut stream| {
            stream.write_all(&frame(credentials())).unwrap();
        });
        assert!(broker
            .credentials(Instant::now() + Duration::from_secs(2))
            .is_ok());
        assert_eq!(
            server.join().unwrap().request,
            Some(Request::Credentials(SeedCredentialsRequest {}))
        );
    }

    #[test]
    fn broker_socket_rejects_invalid_frames_without_generating_a_seed() {
        let legacy_json = br#"{"ciphertext":null}"#;
        let mut legacy_frame = (legacy_json.len() as u32).to_be_bytes().to_vec();
        legacy_frame.extend_from_slice(legacy_json);
        for reply in [
            0u32.to_le_bytes().to_vec(),
            ((MAX_MESSAGE_BYTES + 1) as u32).to_le_bytes().to_vec(),
            vec![0, 0],
            vec![10, 0, 0, 0, 0x12, 0], // truncated body
            vec![1, 0, 0, 0, 0xff],     // invalid protobuf
            vec![2, 0, 0, 0, 0x7a, 0],  // unknown-only response: no oneof
            legacy_frame,
            frame(credentials()), // wrong operation response
            frame(ciphertext(vec![])),
            frame(ciphertext(vec![0; MAX_CIPHERTEXT_BYTES + 1])),
        ] {
            let (broker, server) = mock_broker(move |mut stream| {
                let _ = stream.write_all(&reply);
            });
            let kms = Kms::default();
            assert!(
                recover_seed(&broker, &kms, None, Instant::now() + Duration::from_secs(2)).is_err()
            );
            assert_eq!(kms.generates.get(), 0);
            assert_eq!(kms.decrypts.get(), 0);
            server.join().unwrap();
        }
    }

    #[test]
    fn only_explicit_not_found_on_load_means_absent() {
        let (broker, server) = mock_broker(|mut stream| {
            stream
                .write_all(&frame(Response::NotFound(SeedNotFound {})))
                .unwrap();
        });
        assert!(broker
            .load(Instant::now() + Duration::from_secs(2))
            .unwrap()
            .is_none());
        server.join().unwrap();
        let (broker, server) = mock_broker(|mut stream| {
            stream
                .write_all(&frame(Response::NotFound(SeedNotFound {})))
                .unwrap();
        });
        assert!(broker
            .create(&[17; 64], Instant::now() + Duration::from_secs(2))
            .is_err());
        server.join().unwrap();
    }

    #[test]
    fn credentials_reject_wrong_variants_invalid_utf8_and_oversized_fields() {
        for reply in [
            Response::NotFound(SeedNotFound {}),
            ciphertext(vec![17; 64]),
            Response::Credentials(SeedCredentials::default()),
            Response::Credentials(SeedCredentials {
                access_key_id: Bytes::from_static(b"AKID"),
                secret_access_key: Bytes::from_static(&[0xff]),
                session_token: Bytes::new(),
            }),
            Response::Credentials(SeedCredentials {
                access_key_id: Bytes::from_static(b"AKID"),
                secret_access_key: Bytes::from_static(b"secret"),
                session_token: Bytes::from(vec![b'a'; 16 * 1024 + 1]),
            }),
        ] {
            let (broker, server) = mock_broker(move |mut stream| {
                stream.write_all(&frame(reply)).unwrap();
            });
            assert!(broker
                .credentials(Instant::now() + Duration::from_secs(2))
                .is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn broker_error_categories_are_preserved_without_host_text_or_creation() {
        use SeedStorageErrorCode::*;
        for (code, expected) in [
            (Configuration as i32, CustodyFailure::Configuration),
            (SeedIdNotAllowed as i32, CustodyFailure::Configuration),
            (AccessDenied as i32, CustodyFailure::AccessDenied),
            (AwsUnavailable as i32, CustodyFailure::Unavailable),
            (Busy as i32, CustodyFailure::Unavailable),
            (OperationTimeout as i32, CustodyFailure::Unavailable),
            (RequestTimeout as i32, CustodyFailure::Unavailable),
            (InvalidCiphertext as i32, CustodyFailure::InvalidCiphertext),
            (Internal as i32, CustodyFailure::Internal),
            (InvalidFrame as i32, CustodyFailure::InvalidResponse),
            (InvalidRequest as i32, CustodyFailure::InvalidResponse),
            (ResponseTooLarge as i32, CustodyFailure::InvalidResponse),
            (Unspecified as i32, CustodyFailure::InvalidResponse),
            (999, CustodyFailure::InvalidResponse),
        ] {
            let (broker, server) = mock_broker(move |mut stream| {
                let mut reply = SeedStorageResponse {
                    response: Some(Response::Error(SeedStorageError { code })),
                }
                .encode_to_vec();
                // An unknown string field must never be echoed into errors/logs.
                let text = b"sensitive-host-text";
                reply.extend_from_slice(&[0x7a, text.len() as u8]);
                reply.extend_from_slice(text);
                stream
                    .write_all(&(reply.len() as u32).to_le_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            });
            let kms = Kms::default();
            let error = recover_seed(&broker, &kms, None, Instant::now() + Duration::from_secs(2))
                .unwrap_err();
            assert!(matches!(error, EnclaveError::Custody { failure, .. } if failure == expected));
            assert!(!error.to_string().contains("sensitive-host-text"));
            assert_eq!(kms.generates.get(), 0);
            assert_eq!(kms.decrypts.get(), 0);
            server.join().unwrap();
        }
    }

    #[test]
    fn broker_deadline_bounds_prefix_and_body_trickle() {
        for trickle_prefix in [true, false] {
            let (broker, server) = mock_broker(move |mut stream| {
                let response = frame(ciphertext(vec![17; 64]));
                let bytes = if trickle_prefix {
                    &response[..]
                } else {
                    stream.write_all(&response[..4]).unwrap();
                    &response[4..]
                };
                for byte in bytes {
                    std::thread::sleep(Duration::from_millis(25));
                    if stream.write_all(&[*byte]).is_err() {
                        break;
                    }
                }
            });
            let started = Instant::now();
            assert!(broker.load(started + Duration::from_millis(70)).is_err());
            assert!(started.elapsed() < Duration::from_millis(500));
            server.join().unwrap();
        }
    }

    #[test]
    fn repeated_broker_operations_share_one_deadline() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let broker = SeedBroker {
            address: listener.local_addr().unwrap(),
            seed_id: "pool-1".into(),
        };
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let _: SeedStorageRequest = framing::read_message(&mut stream).unwrap();
                std::thread::sleep(Duration::from_millis(80));
                let _ = stream.write_all(&frame(Response::NotFound(SeedNotFound {})));
            }
        });
        let deadline = Instant::now() + Duration::from_millis(130);
        assert!(broker.load(deadline).unwrap().is_none());
        assert!(broker.load(deadline).is_err());
        server.join().unwrap();
    }

    #[test]
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    fn vsock_connect_rejects_expired_deadline_before_opening_a_socket() {
        // This also runs on Linux hosts without the Nitro VSOCK device.
        let error = connect_vsock(BROKER_VSOCK_PORT, Instant::now()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn exhausted_recovery_budget_never_generates_or_decrypts() {
        let store = Store::default();
        let kms = Kms::default();
        assert!(recover_seed(&store, &kms, None, Instant::now()).is_err());
        assert_eq!(kms.generates.get(), 0);
        assert_eq!(kms.decrypts.get(), 0);
        assert!(store.saved.borrow().is_none());
    }
}
