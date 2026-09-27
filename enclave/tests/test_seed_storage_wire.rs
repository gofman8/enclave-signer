//! Credential fields must retain the zeroizing frame owner during protobuf
//! decoding, including replacement fields and failures after partial decoding.

use prost::{bytes::Bytes, Message};
use std::{
    ops::Range,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use utexo_bridge_enclave::proto::{
    seed_storage_response::Response, SeedCredentials, SeedStorageResponse,
};
use zeroize::{Zeroize, Zeroizing};

struct FrameOwner {
    bytes: Zeroizing<Vec<u8>>,
    erased: Arc<AtomicBool>,
}

impl AsRef<[u8]> for FrameOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for FrameOwner {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.erased
            .store(self.bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
    }
}

fn owned_frame(bytes: Vec<u8>) -> (Bytes, Range<usize>, Arc<AtomicBool>) {
    let start = bytes.as_ptr() as usize;
    let range = start..start + bytes.len();
    let erased = Arc::new(AtomicBool::new(false));
    (
        Bytes::from_owner(FrameOwner {
            bytes: Zeroizing::new(bytes),
            erased: erased.clone(),
        }),
        range,
        erased,
    )
}

fn credentials() -> SeedCredentials {
    SeedCredentials {
        access_key_id: Bytes::from_static(b"AKID"),
        secret_access_key: Bytes::from_static(b"secret"),
        session_token: Bytes::from_static(b"token"),
    }
}

fn response() -> SeedStorageResponse {
    SeedStorageResponse {
        response: Some(Response::Credentials(credentials())),
    }
}

fn assert_backed_by_frame(credentials: &SeedCredentials, frame: &Range<usize>) {
    for field in [
        &credentials.access_key_id,
        &credentials.secret_access_key,
        &credentials.session_token,
    ] {
        let start = field.as_ptr() as usize;
        assert!(!field.is_empty());
        assert!(start >= frame.start && start + field.len() <= frame.end);
    }
}

#[test]
fn credential_response_retains_and_erases_the_original_frame() {
    let (frame, range, erased) = owned_frame(response().encode_to_vec());
    let response = SeedStorageResponse::decode(frame).unwrap();
    let Some(Response::Credentials(credentials)) = response.response.as_ref() else {
        panic!("expected credential response");
    };
    assert_backed_by_frame(credentials, &range);
    assert!(!erased.load(Ordering::SeqCst));
    drop(response);
    assert!(erased.load(Ordering::SeqCst));
}

#[test]
fn duplicate_credential_fields_share_the_original_frame() {
    let mut bytes = credentials().encode_to_vec();
    SeedCredentials {
        access_key_id: Bytes::from_static(b"REPLACEMENT"),
        ..Default::default()
    }
    .encode(&mut bytes)
    .unwrap();
    let (frame, range, erased) = owned_frame(bytes);
    let credentials = SeedCredentials::decode(frame).unwrap();
    assert_eq!(credentials.access_key_id, b"REPLACEMENT"[..]);
    assert_backed_by_frame(&credentials, &range);
    assert!(!erased.load(Ordering::SeqCst));
    drop(credentials);
    assert!(erased.load(Ordering::SeqCst));
}

#[test]
fn truncated_credentials_release_and_erase_partially_decoded_fields() {
    let mut bytes = credentials().encode_to_vec();
    bytes.pop();
    let (frame, _, erased) = owned_frame(bytes);
    assert!(SeedCredentials::decode(frame).is_err());
    assert!(erased.load(Ordering::SeqCst));
}

#[test]
fn malformed_response_erases_previously_decoded_credentials() {
    let mut bytes = response().encode_to_vec();
    bytes.push(0xff); // Unterminated next field key after valid credentials.
    let (frame, _, erased) = owned_frame(bytes);
    assert!(SeedStorageResponse::decode(frame).is_err());
    assert!(erased.load(Ordering::SeqCst));
}
