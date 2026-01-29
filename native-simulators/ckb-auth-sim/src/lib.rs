//! Native simulator for ckb-auth
//!
//! This is a mock implementation that verifies secp256k1 signatures natively.
//! It's used for coverage testing when the real ckb-auth (RISC-V binary)
//! cannot be executed in native-simulator mode.

use blake2b_rs::Blake2bBuilder;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Script info setter - required by the native-simulator runtime
#[unsafe(no_mangle)]
pub extern "C" fn __set_script_info(ptr: *mut std::ffi::c_void, tx_ctx_id: u64, proc_ctx_id: u64) {
    ckb_std::set_script_info(ptr, tx_ctx_id, proc_ctx_id)
}

/// Entry point called by the native-simulator runtime
#[unsafe(no_mangle)]
pub extern "C" fn __ckb_std_main(argc: i32, argv: *const *const c_char) -> i8 {
    match verify_auth(argc, argv) {
        Ok(_) => 0,
        Err(code) => code,
    }
}

fn verify_auth(argc: i32, argv: *const *const c_char) -> Result<(), i8> {
    // ckb-auth expects 4 arguments:
    // argv[0] = algorithm_id (hex)
    // argv[1] = signature (hex, 65 bytes)
    // argv[2] = message (hex, 32 bytes)
    // argv[3] = pubkey_hash (hex, 20 bytes)

    if argc < 4 {
        return Err(1);
    }

    // Parse arguments from argv
    let get_arg = |idx: usize| -> Result<&str, i8> {
        if idx >= argc as usize {
            return Err(1);
        }
        unsafe {
            let ptr = *argv.add(idx);
            CStr::from_ptr(ptr).to_str().map_err(|_| 1i8)
        }
    };

    let algorithm_id_hex = get_arg(0)?;
    let signature_hex = get_arg(1)?;
    let message_hex = get_arg(2)?;
    let pubkey_hash_hex = get_arg(3)?;

    // Parse algorithm ID
    let algorithm_id = hex_decode(algorithm_id_hex).map_err(|_| 2i8)?;

    if algorithm_id.is_empty() {
        return Err(2);
    }

    // Only support secp256k1 (algorithm_id = 0)
    if algorithm_id[0] != 0 {
        return Err(3);
    }

    // Parse signature (65 bytes: 64-byte compact signature + 1-byte recovery id)
    let signature = hex_decode(signature_hex).map_err(|_| 4i8)?;

    if signature.len() != 65 {
        return Err(4);
    }

    // Parse message (32 bytes)
    let message = hex_decode(message_hex).map_err(|_| 5i8)?;

    if message.len() != 32 {
        return Err(5);
    }

    // Parse pubkey_hash (20 bytes)
    let expected_pubkey_hash = hex_decode(pubkey_hash_hex).map_err(|_| 6i8)?;

    if expected_pubkey_hash.len() != 20 {
        return Err(6);
    }

    // Verify secp256k1 signature
    verify_secp256k1(&signature, &message, &expected_pubkey_hash)
}

fn verify_secp256k1(
    signature: &[u8],
    message: &[u8],
    expected_pubkey_hash: &[u8],
) -> Result<(), i8> {
    let secp = Secp256k1::verification_only();

    // Extract recovery id (last byte) and compact signature (first 64 bytes)
    let recovery_id = RecoveryId::from_i32(signature[64] as i32).map_err(|_| 7i8)?;

    let recoverable_sig =
        RecoverableSignature::from_compact(&signature[..64], recovery_id).map_err(|_| 7i8)?;

    // Create message
    let msg = Message::from_digest_slice(message).map_err(|_| 8i8)?;

    // Recover public key
    let pubkey = secp
        .recover_ecdsa(&msg, &recoverable_sig)
        .map_err(|_| 9i8)?;

    // Compute blake2b-256 hash of the serialized public key (first 20 bytes)
    let pubkey_bytes = pubkey.serialize();
    let pubkey_hash = blake2b_256(&pubkey_bytes);
    let pubkey_hash_20 = &pubkey_hash[..20];

    // Compare with expected hash
    if pubkey_hash_20 != expected_pubkey_hash {
        return Err(10);
    }

    Ok(())
}

/// blake2b-256 hash with CKB personalization
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(data);
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    result
}

/// Decode hex string to bytes
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let high = hex_char_to_nibble(chunk[0])?;
        let low = hex_char_to_nibble(chunk[1])?;
        result.push((high << 4) | low);
    }
    Ok(result)
}

fn hex_char_to_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

// Flush LLVM coverage data when the shared library is unloaded.
#[cfg(coverage)]
mod coverage_flush {
    unsafe extern "C" {
        fn __llvm_profile_write_file() -> i32;
    }

    #[ctor::dtor]
    fn flush_coverage() {
        unsafe {
            __llvm_profile_write_file();
        }
    }
}
