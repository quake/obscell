#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

use alloc::ffi::CString;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::core::ScriptHashType,
    error::SysError,
    high_level::{exec_cell, load_script, load_tx_hash, load_witness_args},
};
use hex::encode;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
// By default, the following heap configuration is used:
// * 16KB fixed heap
// * 1.2MB(rounded up to be 16-byte aligned) dynamic heap
// * Minimal memory block in dynamic heap is 64 bytes
// For more details, please refer to ckb-std's default_alloc macro
// and the buddy-alloc alloc implementation.
ckb_std::default_alloc!(16384, 1258306, 64);

include!(concat!(env!("OUT_DIR"), "/ckb_auth_code_hash.rs"));

#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    ArgsLengthNotEnough,
    SignatureLengthNotEnough,
    AuthError,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        match err {
            SysError::IndexOutOfBound => Self::IndexOutOfBound,
            SysError::ItemMissing => Self::ItemMissing,
            SysError::LengthNotEnough(_) => Self::LengthNotEnough,
            SysError::Encoding => Self::Encoding,
            SysError::Unknown(err_code) => panic!("unexpected sys error {}", err_code),
            _ => panic!("unreachable spawn related sys error"),
        }
    }
}

pub fn program_entry() -> i8 {
    match auth() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

fn auth() -> Result<(), Error> {
    let algorithm_id_str = CString::new(encode([0u8])).unwrap();
    let signature_str = {
        let signature = {
            let witness_args = load_witness_args(0, Source::GroupInput)?;
            let signature = witness_args
                .lock()
                .to_opt()
                .map(|b| b.raw_data())
                .unwrap_or_default();
            if signature.len() != 65 {
                return Err(Error::SignatureLengthNotEnough);
            }
            signature
        };
        CString::new(encode(signature)).unwrap()
    };
    let message_str = {
        let message = load_tx_hash()?;
        CString::new(encode(message)).unwrap()
    };
    let pubkey_hash_str = {
        let pubkey_hash = {
            let mut hash = [0u8; 20];
            let script_args = load_script()?.args().raw_data();
            // args is P | Q', P is 33 bytes, Q' is 20 bytes
            if script_args.len() != 53 {
                return Err(Error::ArgsLengthNotEnough);
            }
            hash.copy_from_slice(&script_args[33..53]);
            hash
        };
        CString::new(encode(pubkey_hash)).unwrap()
    };

    let args = [
        algorithm_id_str.as_c_str(),
        signature_str.as_c_str(),
        message_str.as_c_str(),
        pubkey_hash_str.as_c_str(),
    ];

    exec_cell(&CKB_AUTH_CODE_HASH, ScriptHashType::Data2, &args).map_err(|_| Error::AuthError)?;
    Ok(())
}
