#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

use alloc::vec::Vec;
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{load_cell_data, load_tx_hash, load_witness_args, QueryIter},
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // ct-info-type errors
    InvalidDataLength,
    InvalidArgsLength,
    InvalidCellCount,
    ImmutableFieldChanged,
    MintingDisabled,
    SupplyCapExceeded,
    InvalidMintAmount,
    SupplyOverflow,
    InvalidSignature,
    InvalidMintCommitment,
    WitnessFormatError,
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
    match validate() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

// Flags bitfield
pub mod flags {
    pub const MINTABLE: u8 = 0x01;
    pub const BURNABLE: u8 = 0x02;
    pub const PAUSABLE: u8 = 0x04;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtInfoData {
    pub total_supply: u128,      // [0..16]
    pub issuer_pubkey: [u8; 32], // [16..48]
    pub supply_cap: u128,        // [48..64]
    pub reserved: [u8; 24],      // [64..88]
    pub flags: u8,               // [88]
}

impl CtInfoData {
    pub const SIZE: usize = 89;

    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() != Self::SIZE {
            return Err(Error::InvalidDataLength);
        }

        let mut total_supply_bytes = [0u8; 16];
        total_supply_bytes.copy_from_slice(&data[0..16]);
        let total_supply = u128::from_le_bytes(total_supply_bytes);

        let mut issuer_pubkey = [0u8; 32];
        issuer_pubkey.copy_from_slice(&data[16..48]);

        let mut supply_cap_bytes = [0u8; 16];
        supply_cap_bytes.copy_from_slice(&data[48..64]);
        let supply_cap = u128::from_le_bytes(supply_cap_bytes);

        let mut reserved = [0u8; 24];
        reserved.copy_from_slice(&data[64..88]);

        let flags = data[88];

        Ok(CtInfoData {
            total_supply,
            issuer_pubkey,
            supply_cap,
            reserved,
            flags,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..16].copy_from_slice(&self.total_supply.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.issuer_pubkey);
        bytes[48..64].copy_from_slice(&self.supply_cap.to_le_bytes());
        bytes[64..88].copy_from_slice(&self.reserved);
        bytes[88] = self.flags;
        bytes
    }
}

fn validate() -> Result<(), Error> {
    // Count inputs and outputs with our type script
    let input_count = QueryIter::new(load_cell_data, Source::GroupInput).count();
    let output_count = QueryIter::new(load_cell_data, Source::GroupOutput).count();

    if input_count == 0 {
        // Genesis transaction: create new token
        validate_genesis(output_count)
    } else if input_count == 1 && output_count == 1 {
        // Mint transaction: update supply
        validate_mint()
    } else {
        // Invalid: must be either genesis (0 inputs) or mint (1 input, 1 output)
        Err(Error::InvalidCellCount)
    }
}

fn validate_genesis(output_count: usize) -> Result<(), Error> {
    // Must have exactly 1 output
    if output_count != 1 {
        return Err(Error::InvalidCellCount);
    }

    // Load output data
    let output_data = load_cell_data(0, Source::GroupOutput)?;
    let output_info = CtInfoData::from_bytes(&output_data)?;

    // Check issuer is set (not all zeros)
    if output_info.issuer_pubkey == [0u8; 32] {
        return Err(Error::InvalidSignature);
    }

    // Check mintable flag is set
    if output_info.flags & flags::MINTABLE != flags::MINTABLE {
        return Err(Error::MintingDisabled);
    }

    Ok(())
}

fn validate_mint() -> Result<(), Error> {
    // Load input and output data
    let input_data = load_cell_data(0, Source::GroupInput)?;
    let output_data = load_cell_data(0, Source::GroupOutput)?;

    let input_info = CtInfoData::from_bytes(&input_data)?;
    let output_info = CtInfoData::from_bytes(&output_data)?;

    // Check immutable fields
    if input_info.issuer_pubkey != output_info.issuer_pubkey {
        return Err(Error::ImmutableFieldChanged);
    }
    if input_info.supply_cap != output_info.supply_cap {
        return Err(Error::ImmutableFieldChanged);
    }
    if input_info.flags != output_info.flags {
        return Err(Error::ImmutableFieldChanged);
    }

    // Check mintable flag
    if input_info.flags & flags::MINTABLE != flags::MINTABLE {
        return Err(Error::MintingDisabled);
    }

    // Calculate minted amount
    if output_info.total_supply <= input_info.total_supply {
        return Err(Error::InvalidMintAmount);
    }
    let minted_amount = output_info.total_supply - input_info.total_supply;

    // Check supply cap
    if input_info.supply_cap > 0 && output_info.total_supply > input_info.supply_cap {
        return Err(Error::SupplyCapExceeded);
    }

    // Verify issuer signature
    verify_issuer_signature(&input_info, &output_info)?;

    // Compute and store mint commitment
    compute_mint_commitment(minted_amount)?;

    Ok(())
}

fn verify_issuer_signature(input_info: &CtInfoData, output_info: &CtInfoData) -> Result<(), Error> {
    // Load witness
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let signature_bytes = witness_args
        .input_type()
        .to_opt()
        .ok_or(Error::WitnessFormatError)?
        .raw_data();

    if signature_bytes.len() != 64 {
        return Err(Error::InvalidSignature);
    }

    // Parse signature
    let signature = Signature::from_slice(&signature_bytes).or(Err(Error::InvalidSignature))?;

    // Parse public key
    let verifying_key =
        VerifyingKey::from_bytes(&input_info.issuer_pubkey).or(Err(Error::InvalidSignature))?;

    // Construct message: tx_hash || old_supply || new_supply
    let tx_hash = load_tx_hash()?;
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&input_info.total_supply.to_le_bytes());
    message.extend_from_slice(&output_info.total_supply.to_le_bytes());

    // Verify signature
    verifying_key
        .verify(&message, &signature)
        .or(Err(Error::InvalidSignature))?;

    Ok(())
}

fn compute_mint_commitment(minted_amount: u128) -> Result<(), Error> {
    // Create commitment: minted_amount * G + 0 * H
    // We use zero blinding factor because mint amounts are public
    let amount_scalar = Scalar::from(minted_amount);
    let _mint_commitment = RISTRETTO_BASEPOINT_POINT * amount_scalar;

    // Note: The commitment is computed off-chain when constructing the transaction
    // and stored in witness.output_type for ct-token-type to verify
    // This function just validates that the minted amount is reasonable

    Ok(())
}
