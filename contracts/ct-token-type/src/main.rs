#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{
        load_cell_data, load_cell_type_hash, load_script, load_tx_hash, load_witness_args,
        QueryIter,
    },
};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use merlin::Transcript;

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

#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    InvalidInput,
    InvalidOutput,
    InputOutputSumMismatch,
    InvalidRangeProofWitnessFormat,
    InvalidRangeProof,
    InvalidMintCommitment,
    MissingCtInfoType,
    InvalidScriptArgs,
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
    let inputs = QueryIter::new(load_cell_data, Source::GroupInput);
    let mut input_sum = RistrettoPoint::default();
    for i in inputs {
        // Support both v1 (64B) and v2 (72B) cell data formats
        // Only first 32 bytes (commitment) are used for verification
        if i.len() < 64 {
            return Err(Error::InvalidInput);
        }
        let point = CompressedRistretto::from_slice(&i[0..32])
            .ok()
            .and_then(|cr| cr.decompress())
            .ok_or(Error::InvalidInput)?;
        input_sum += point;
    }

    let outputs = QueryIter::new(load_cell_data, Source::GroupOutput);
    let mut value_commitments = alloc::vec::Vec::new();
    let mut output_sum = RistrettoPoint::default();
    for i in outputs {
        // Support both v1 (64B) and v2 (72B) cell data formats
        // Only first 32 bytes (commitment) are used for verification
        if i.len() < 64 {
            return Err(Error::InvalidOutput);
        }
        let cr = CompressedRistretto::from_slice(&i[0..32]).or(Err(Error::InvalidOutput))?;
        let point = cr.decompress().ok_or(Error::InvalidOutput)?;
        output_sum += point;
        value_commitments.push(cr);
    }

    // Check for mint commitment in witness
    // If ct-info-type is present, it will provide mint_commitment in witness[0].input_type
    let witness_args = load_witness_args(0, Source::GroupOutput)?;
    let mint_commitment_opt = witness_args.input_type().to_opt();

    if let Some(mint_commitment_bytes) = mint_commitment_opt {
        // This is a mint transaction - MUST verify ct-info-type exists

        // Load script args to get expected ct-info-type script hash
        let script = load_script()?;
        let script_args = script.args().raw_data();

        // Script args format: [ct_info_script_hash: 32 bytes]
        // This is the complete script hash of the expected ct-info-type cell,
        // which uniquely identifies the token (includes code_hash + hash_type + args/type_id)
        if script_args.len() < 32 {
            return Err(Error::InvalidScriptArgs);
        }

        let expected_ct_info_script_hash: [u8; 32] = script_args[0..32].try_into().unwrap();

        // Verify ct-info-type with matching script hash exists in transaction inputs
        let ct_info_found = verify_ct_info_exists(&expected_ct_info_script_hash)?;
        if !ct_info_found {
            return Err(Error::MissingCtInfoType);
        }

        let mint_commitment_data = mint_commitment_bytes.raw_data();
        if mint_commitment_data.len() != 32 {
            return Err(Error::InvalidMintCommitment);
        }

        let mint_commitment = CompressedRistretto::from_slice(&mint_commitment_data)
            .ok()
            .and_then(|cr| cr.decompress())
            .ok_or(Error::InvalidMintCommitment)?;

        // For mint: input_sum + mint_commitment == output_sum
        if input_sum + mint_commitment != output_sum {
            return Err(Error::InputOutputSumMismatch);
        }
    } else {
        // Regular transfer: input_sum == output_sum
        if input_sum != output_sum {
            return Err(Error::InputOutputSumMismatch);
        }
    }

    // Must have at least one output to verify
    if value_commitments.is_empty() {
        return Err(Error::InvalidOutput);
    }

    let witness_args = load_witness_args(0, Source::GroupOutput)?
        .output_type()
        .to_opt();

    let rp = RangeProof::from_bytes(&witness_args.unwrap_or_default().raw_data())
        .or(Err(Error::InvalidRangeProofWitnessFormat))?;
    let bp_gens = BulletproofGens::new(64, value_commitments.len());
    let pc_gens = PedersenGens::default();
    let mut verifier_transcript = Transcript::new(b"ct-token-type");
    let mut rng = TxHashRng::new();

    rp.verify_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &value_commitments,
        32,
        &mut rng,
    )
    .or(Err(Error::InvalidRangeProof))
}

pub struct TxHashRng {
    s0: u64,
    s1: u64,
}

impl Default for TxHashRng {
    fn default() -> Self {
        Self::new()
    }
}

impl TxHashRng {
    pub fn new() -> Self {
        let seed = load_tx_hash().unwrap();
        let s0 = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        let s1 = u64::from_le_bytes(seed[8..16].try_into().unwrap());
        Self { s0, s1 }
    }

    fn next_u64_internal(&mut self) -> u64 {
        let s0 = self.s0;
        let mut s1 = self.s1;
        let result = s0.wrapping_add(s1);

        s1 ^= s0;
        self.s0 = s0.rotate_left(55) ^ s1 ^ (s1 << 14);
        self.s1 = s1.rotate_left(36);

        result
    }
}

impl rand_core::RngCore for TxHashRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64_internal() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64_internal()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let r = self.next_u64_internal();
            let bytes = r.to_le_bytes();
            let take = core::cmp::min(8, dest.len() - i);
            dest[i..i + take].copy_from_slice(&bytes[..take]);
            i += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TxHashRng {}

/// Verify that ct-info-type script exists in the transaction inputs
/// with matching script hash.
/// This is required for mint transactions to ensure the mint_commitment
/// was validated by the correct ct-info-type cell.
///
/// SECURITY: By comparing the full script hash (which includes code_hash + hash_type + args),
/// we prevent attackers from using their own ct-info cell to mint tokens for other token types.
fn verify_ct_info_exists(expected_ct_info_script_hash: &[u8; 32]) -> Result<bool, Error> {
    // Iterate through all inputs to find a cell with matching ct-info-type script hash
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, Source::Input) {
            Ok(Some(type_hash)) => {
                // load_cell_type_hash returns the script hash directly
                if type_hash == *expected_ct_info_script_hash {
                    return Ok(true);
                }
            }
            Ok(None) => {
                // Cell has no type script, continue
            }
            Err(SysError::IndexOutOfBound) => {
                // No more cells to check
                break;
            }
            Err(e) => return Err(e.into()),
        }
        index += 1;
    }
    Ok(false)
}
