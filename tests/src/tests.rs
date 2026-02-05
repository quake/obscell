use crate::Loader;
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

// ct-info-type constants
const MINTABLE: u8 = 0x01;
const CT_INFO_DATA_SIZE: usize = 57;

/// Create ct-info-type cell data (57 bytes)
/// Layout: total_supply(16) + supply_cap(16) + reserved(24) + flags(1)
fn create_ct_info_data(total_supply: u128, supply_cap: u128, flags: u8) -> Bytes {
    let mut data = vec![0u8; CT_INFO_DATA_SIZE];
    data[0..16].copy_from_slice(&total_supply.to_le_bytes());
    data[16..32].copy_from_slice(&supply_cap.to_le_bytes());
    // reserved[32..56] stays zero
    data[56] = flags;
    data.into()
}

/// Calculate Type ID for ct-info-type
fn calculate_type_id(first_input: &CellInput, output_index: u64) -> [u8; 32] {
    use ckb_testtool::ckb_hash::blake2b_256;
    let mut data = Vec::new();
    data.extend_from_slice(first_input.as_slice());
    data.extend_from_slice(&output_index.to_le_bytes());
    blake2b_256(&data)
}

/// Compute mint commitment: amount * G + 0 * H
fn compute_mint_commitment(minted_amount: u128) -> Bytes {
    let amount_scalar = Scalar::from(minted_amount);
    let commitment = RISTRETTO_BASEPOINT_POINT * amount_scalar;
    Bytes::from(commitment.compress().to_bytes().to_vec())
}

/// Deploy ckb-auth binary and register its native simulator.
/// Returns the OutPoint of the deployed cell.
#[cfg(feature = "native-simulator")]
fn deploy_ckb_auth(context: &mut Context) -> OutPoint {
    use std::path::PathBuf;

    let ckb_auth_bin = Loader::default().load_binary("../../contracts/ckb-auth/auth");
    let code_hash = CellOutput::calc_data_hash(&ckb_auth_bin);
    let out_point = context.deploy_cell(ckb_auth_bin);

    // Register the ckb-auth-sim native simulator
    // The path is relative to the target directory
    let mode = std::env::var("MODE").unwrap_or_else(|_| "release".to_string());
    let sim_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target")
        .join(mode)
        .join("libckb_auth_sim.so");

    if sim_path.exists() {
        context.set_simulator(code_hash, sim_path.to_str().unwrap());
    } else {
        panic!(
            "ckb-auth-sim not found at {:?}. Build it with: cargo build -p ckb-auth-sim",
            sim_path
        );
    }

    out_point
}

/// Deploy ckb-auth binary (non-simulator mode).
#[cfg(not(feature = "native-simulator"))]
fn deploy_ckb_auth(context: &mut Context) -> OutPoint {
    let ckb_auth_bin = Loader::default().load_binary("../../contracts/ckb-auth/auth");
    context.deploy_cell(ckb_auth_bin)
}

// Error codes for stealth-lock
#[allow(dead_code)]
mod stealth_lock_error {
    pub const ARGS_LENGTH_NOT_ENOUGH: i8 = 5;
    pub const SIGNATURE_LENGTH_NOT_ENOUGH: i8 = 6;
    pub const AUTH_ERROR: i8 = 7;
}

// Error codes for ct-info-type
// Error codes for ct-info-type
// NOTE: Authorization (signature verification) is handled by the LOCK SCRIPT,
// not the type script. The type script only validates state transitions.
#[allow(dead_code)]
mod ct_info_error {
    pub const INVALID_DATA_LENGTH: i8 = 5;
    pub const INVALID_CELL_COUNT: i8 = 7;
    pub const IMMUTABLE_FIELD_CHANGED: i8 = 8;
    pub const MINTING_DISABLED: i8 = 9;
    pub const SUPPLY_CAP_EXCEEDED: i8 = 10;
    pub const INVALID_MINT_AMOUNT: i8 = 11;
    pub const INVALID_MINT_COMMITMENT: i8 = 13;
    pub const WITNESS_FORMAT_ERROR: i8 = 14;
}

// Error codes for ct-token-type
#[allow(dead_code)]
mod ct_token_error {
    pub const INVALID_INPUT: i8 = 5;
    pub const INVALID_OUTPUT: i8 = 6;
    pub const INPUT_OUTPUT_SUM_MISMATCH: i8 = 7;
    pub const INVALID_RANGE_PROOF_WITNESS_FORMAT: i8 = 8;
    pub const INVALID_RANGE_PROOF: i8 = 9;
    pub const INVALID_MINT_COMMITMENT: i8 = 10;
    pub const MISSING_CT_INFO_TYPE: i8 = 11;
    pub const INVALID_SCRIPT_ARGS: i8 = 12;
}

/// Helper to check if an error contains a specific script error code
#[allow(dead_code)]
fn assert_script_error(result: Result<u64, ckb_testtool::ckb_error::Error>, expected_code: i8) {
    let err = result.expect_err("should fail");
    let err_str = format!("{:?}", err);
    // Look for the error code in the error message
    assert!(
        err_str.contains(&format!("error code {}", expected_code))
            || err_str.contains(&format!("ValidationFailure(\"Byte({})\")", expected_code)),
        "Expected error code {}, got: {}",
        expected_code,
        err_str
    );
}

#[test]
fn test_stealth_lock() {
    // deploy contract
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("stealth-lock");
    let ckb_auth_out_point = deploy_ckb_auth(&mut context);

    // prepare script
    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let seckey = SecretKey::new(&mut rng);
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let public_key_hash = blake2b_256(pubkey.serialize())[0..20].to_vec();
    let script_args = [vec![0; 33], public_key_hash].concat();
    let lock_script = context
        .build_script(&contract_out_point, script_args.into())
        .unwrap();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // prepare cell deps
    let dep1 = CellDep::new_builder().out_point(contract_out_point).build();
    let dep2 = CellDep::new_builder().out_point(ckb_auth_out_point).build();
    let cell_deps = vec![dep1, dep2].pack();

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(128)
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(128)
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    let message =
        Message::from_digest(tx.hash().raw_data().to_vec().as_slice().try_into().unwrap());
    let (recovery_id, signature) = secp
        .sign_ecdsa_recoverable(message, &seckey)
        .serialize_compact();
    let witness = [signature.as_slice(), &[i32::from(recovery_id) as u8]].concat();
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(witness)))
        .build();

    let tx = tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes())
        .build();

    // run
    let cycles = context
        .verify_tx(&tx, 10_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

// Note: The following 4 tests are skipped in native-simulator mode because
// ckb-x64-simulator uses lazy_static for TRANSACTION/SETUP which gets cached
// from the first test run. This causes subsequent tests to use stale context
// and return incorrect results. These tests pass correctly in normal mode.

#[test]
#[cfg(not(feature = "native-simulator"))]
fn test_stealth_lock_invalid_signature_length() {
    // Test: Signature length is not 65 bytes (should fail with SignatureLengthNotEnough)
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("stealth-lock");
    let ckb_auth_out_point = deploy_ckb_auth(&mut context);

    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let seckey = SecretKey::new(&mut rng);
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let public_key_hash = blake2b_256(pubkey.serialize())[0..20].to_vec();
    let script_args = [vec![0; 33], public_key_hash].concat();
    let lock_script = context
        .build_script(&contract_out_point, script_args.into())
        .unwrap();

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let dep1 = CellDep::new_builder().out_point(contract_out_point).build();
    let dep2 = CellDep::new_builder().out_point(ckb_auth_out_point).build();
    let cell_deps = vec![dep1, dep2].pack();

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(256)
        .lock(lock_script)
        .build()];

    // Use a 64-byte signature instead of 65 bytes
    let invalid_signature = vec![0u8; 64];
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(invalid_signature)))
        .build();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::new()].pack())
        .witness(witness_args.as_bytes())
        .build();

    let result = context.verify_tx(&tx, 10_000_000);
    assert!(result.is_err(), "should fail with invalid signature length");
    println!("test_stealth_lock_invalid_signature_length: passed (correctly rejected)");
}

#[test]
#[cfg(not(feature = "native-simulator"))]
fn test_stealth_lock_invalid_args_length() {
    // Test: Script args length is not 53 bytes (should fail with ArgsLengthNotEnough)
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("stealth-lock");
    let ckb_auth_out_point = deploy_ckb_auth(&mut context);

    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let seckey = SecretKey::new(&mut rng);
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let public_key_hash = blake2b_256(pubkey.serialize())[0..20].to_vec();

    // Use wrong args length (50 bytes instead of 53)
    let script_args = [vec![0; 30], public_key_hash].concat();
    let lock_script = context
        .build_script(&contract_out_point, script_args.into())
        .unwrap();

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let dep1 = CellDep::new_builder().out_point(contract_out_point).build();
    let dep2 = CellDep::new_builder().out_point(ckb_auth_out_point).build();
    let cell_deps = vec![dep1, dep2].pack();

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(256)
        .lock(lock_script)
        .build()];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::new()].pack())
        .build();

    // Sign the transaction properly
    let message =
        Message::from_digest(tx.hash().raw_data().to_vec().as_slice().try_into().unwrap());
    let (recovery_id, signature) = secp
        .sign_ecdsa_recoverable(message, &seckey)
        .serialize_compact();
    let witness = [signature.as_slice(), &[i32::from(recovery_id) as u8]].concat();
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(witness)))
        .build();

    let tx = tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes())
        .build();

    let result = context.verify_tx(&tx, 10_000_000);
    assert!(result.is_err(), "should fail with invalid args length");
    println!("test_stealth_lock_invalid_args_length: passed (correctly rejected)");
}

#[test]
#[cfg(not(feature = "native-simulator"))]
fn test_stealth_lock_wrong_signature() {
    // Test: Wrong signature (signed with different key) should fail with AuthError
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("stealth-lock");
    let ckb_auth_out_point = deploy_ckb_auth(&mut context);

    let secp = Secp256k1::new();
    let mut rng = rand::rng();

    // Generate the keypair used for the lock script
    let seckey = SecretKey::new(&mut rng);
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let public_key_hash = blake2b_256(pubkey.serialize())[0..20].to_vec();
    let script_args = [vec![0; 33], public_key_hash].concat();
    let lock_script = context
        .build_script(&contract_out_point, script_args.into())
        .unwrap();

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let dep1 = CellDep::new_builder().out_point(contract_out_point).build();
    let dep2 = CellDep::new_builder().out_point(ckb_auth_out_point).build();
    let cell_deps = vec![dep1, dep2].pack();

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(256)
        .lock(lock_script)
        .build()];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::new()].pack())
        .build();

    // Sign with a DIFFERENT key (wrong key)
    let wrong_seckey = SecretKey::new(&mut rng);
    let message =
        Message::from_digest(tx.hash().raw_data().to_vec().as_slice().try_into().unwrap());
    let (recovery_id, signature) = secp
        .sign_ecdsa_recoverable(message, &wrong_seckey)
        .serialize_compact();
    let witness = [signature.as_slice(), &[i32::from(recovery_id) as u8]].concat();
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(witness)))
        .build();

    let tx = tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes())
        .build();

    let result = context.verify_tx(&tx, 10_000_000);
    assert!(result.is_err(), "should fail with wrong signature");
    println!("test_stealth_lock_wrong_signature: passed (correctly rejected)");
}

#[test]
fn test_ct_token_mint_without_ct_info_type() {
    // Test: Mint transaction with mint_commitment but WITHOUT ct-info-type should fail
    // This tests the security fix that prevents unauthorized minting
    let mut context = Context::default();

    // Deploy only ct-token-type (not ct-info-type in the transaction inputs)
    let ct_token_out_point = context.deploy_cell_by_name("ct-token-type");
    let ct_info_out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Get ct-info-type code_hash for ct-token-type script args
    let ct_info_type_script = context
        .build_script(&ct_info_out_point, Bytes::from(vec![0u8; 33]))
        .unwrap();
    let ct_info_code_hash: [u8; 32] = ct_info_type_script.code_hash().unpack();

    // Create ct-token-type script with ct-info-type code_hash in args
    let type_script = context
        .build_script(&ct_token_out_point, Bytes::from(ct_info_code_hash.to_vec()))
        .unwrap();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    // Create a "zero" input cell - NO ct-info-type input!
    let v_in = Scalar::from(0u64);
    let r_in = Scalar::random(&mut rng);
    let c_in = pc_gens.commit(v_in, r_in);
    let mut input_data = c_in.compress().to_bytes().to_vec();
    input_data.extend_from_slice(&[0u8; 32]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data.into(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Try to mint 100 tokens without ct-info-type
    let mint_amount = 100u64;
    let mint_scalar = Scalar::from(mint_amount);
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);

    // Output: 100 tokens (attempted mint)
    let r_out = r_in;
    let v_out = Scalar::from(mint_amount);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut output_data = c_out.compress().to_bytes().to_vec();
    output_data.extend_from_slice(&[0u8; 32]);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    // Create range proof
    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[mint_amount],
        &[r_out],
        32,
        &mut rng,
    )
    .unwrap();

    // Put mint_commitment in input_type and range_proof in output_type
    // This would have worked before the fix!
    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(
            mint_commitment.compress().to_bytes().to_vec(),
        )))
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(output_data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    // Should fail with MissingCtInfoType error
    let result = context.verify_tx(&tx, 1_000_000_000);
    assert!(
        result.is_err(),
        "should fail without ct-info-type in transaction"
    );
    println!(
        "test_ct_token_mint_without_ct_info_type: passed (correctly rejected unauthorized mint)"
    );
}

#[test]
fn test_ct_token_mint_invalid_script_args() {
    // Test: Mint with script args too short (less than 32 bytes) should fail
    let mut context = Context::default();

    let ct_token_out_point = context.deploy_cell_by_name("ct-token-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Create ct-token-type script with INVALID args (only 1 byte instead of 32)
    let type_script = context
        .build_script(&ct_token_out_point, Bytes::from(vec![0u8]))
        .unwrap();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    let v_in = Scalar::from(0u64);
    let r_in = Scalar::random(&mut rng);
    let c_in = pc_gens.commit(v_in, r_in);
    let mut input_data = c_in.compress().to_bytes().to_vec();
    input_data.extend_from_slice(&[0u8; 32]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data.into(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Try to mint
    let mint_amount = 100u64;
    let mint_scalar = Scalar::from(mint_amount);
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);

    let r_out = r_in;
    let v_out = Scalar::from(mint_amount);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut output_data = c_out.compress().to_bytes().to_vec();
    output_data.extend_from_slice(&[0u8; 32]);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[mint_amount],
        &[r_out],
        32,
        &mut rng,
    )
    .unwrap();

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(
            mint_commitment.compress().to_bytes().to_vec(),
        )))
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(output_data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    // Should fail with InvalidScriptArgs error
    let result = context.verify_tx(&tx, 1_000_000_000);
    assert!(result.is_err(), "should fail with invalid script args");
    println!("test_ct_token_mint_invalid_script_args: passed (correctly rejected)");
}

// ============================================================================
// HIGH PRIORITY: Invalid Ristretto Point Tests
// ============================================================================

#[test]
fn test_ct_token_invalid_input_ristretto_point() {
    // Test: Input cell data has 64 bytes but first 32 bytes are not a valid Ristretto point
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("ct-token-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    // Create input with 64 bytes but INVALID Ristretto point (all 0xFF bytes)
    // This is 64 bytes total, but first 32 bytes don't form a valid compressed Ristretto point
    let mut invalid_input_data = vec![0xFF; 32]; // Invalid point bytes
    invalid_input_data.extend_from_slice(&[0u8; 32]); // Padding

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        invalid_input_data.into(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Valid output
    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;
    let v_out = Scalar::from(0u64);
    let r_out = Scalar::random(&mut rng);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut output_data = c_out.compress().to_bytes().to_vec();
    output_data.extend_from_slice(&[0u8; 32]);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[0],
        &[r_out],
        32,
        &mut rng,
    )
    .unwrap();

    let witness_args = WitnessArgs::new_builder()
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(output_data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert_script_error(result, ct_token_error::INVALID_INPUT);
    println!("test_ct_token_invalid_input_ristretto_point: passed (correctly rejected)");
}

#[test]
fn test_ct_token_invalid_output_ristretto_point() {
    // Test: Output cell data has 64 bytes but first 32 bytes are not a valid Ristretto point
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("ct-token-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    // Valid input
    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;
    let v_in = Scalar::from(100u64);
    let r_in = Scalar::random(&mut rng);
    let c_in = pc_gens.commit(v_in, r_in);
    let mut input_data = c_in.compress().to_bytes().to_vec();
    input_data.extend_from_slice(&[0u8; 32]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data.into(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Invalid output - 64 bytes but not a valid Ristretto point
    let mut invalid_output_data = vec![0xFF; 32]; // Invalid point bytes
    invalid_output_data.extend_from_slice(&[0u8; 32]); // Padding

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    // We still need a witness, though it won't be verified due to earlier failure
    let witness_args = WitnessArgs::new_builder().build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(invalid_output_data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert_script_error(result, ct_token_error::INVALID_OUTPUT);
    println!("test_ct_token_invalid_output_ristretto_point: passed (correctly rejected)");
}

// ============================================================================
// HIGH PRIORITY: Invalid Mint Commitment Tests
// ============================================================================

#[test]
fn test_ct_token_invalid_mint_commitment_length() {
    // Test: Mint commitment in witness is not 32 bytes
    let mut context = Context::default();

    let ct_token_out_point = context.deploy_cell_by_name("ct-token-type");
    let ct_info_out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Get ct-info-type code_hash
    let ct_info_type_script = context
        .build_script(&ct_info_out_point, Bytes::from(vec![0u8; 33]))
        .unwrap();
    let ct_info_code_hash: [u8; 32] = ct_info_type_script.code_hash().unpack();

    let type_script = context
        .build_script(&ct_token_out_point, Bytes::from(ct_info_code_hash.to_vec()))
        .unwrap();

    // Create ct-info-type input
    let token_id = [43u8; 32];
    let mut ct_info_args = Vec::new();
    ct_info_args.extend_from_slice(&token_id);
    ct_info_args.push(0);
    let ct_info_script = context
        .build_script(&ct_info_out_point, ct_info_args.into())
        .unwrap();

    let old_supply = 0u128;
    let new_supply = 100u128;

    let ct_info_input_data = create_ct_info_data(old_supply, 1_000_000, MINTABLE);
    let ct_info_output_data = create_ct_info_data(new_supply, 1_000_000, MINTABLE);

    let ct_info_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script.clone()))
            .build(),
        ct_info_input_data,
    );
    let ct_info_input = CellInput::new_builder()
        .previous_output(ct_info_input_out_point)
        .build();

    // Create ct-token-type input
    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    let v_in = Scalar::from(0u64);
    let r_in = Scalar::random(&mut rng);
    let c_in = pc_gens.commit(v_in, r_in);
    let mut ct_token_input_data = c_in.compress().to_bytes().to_vec();
    ct_token_input_data.extend_from_slice(&[0u8; 32]);

    let ct_token_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        ct_token_input_data.into(),
    );
    let ct_token_input = CellInput::new_builder()
        .previous_output(ct_token_input_out_point)
        .build();

    // Output
    let minted_amount = new_supply - old_supply;
    let mint_scalar = Scalar::from(minted_amount as u64);
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);

    let r_out = r_in;
    let v_out = Scalar::from(minted_amount as u64);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut ct_token_output_data = c_out.compress().to_bytes().to_vec();
    ct_token_output_data.extend_from_slice(&[0u8; 32]);

    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[minted_amount as u64],
        &[r_out],
        32,
        &mut rng,
    )
    .unwrap();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script))
            .build(),
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![
        CellDep::new_builder().out_point(ct_info_out_point).build(),
        CellDep::new_builder().out_point(ct_token_out_point).build(),
    ]
    .pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(ct_info_input)
        .input(ct_token_input)
        .outputs(outputs)
        .outputs_data(vec![ct_info_output_data, Bytes::from(ct_token_output_data)].pack())
        .build();

    let tx = context.complete_tx(tx);

    let mint_commitment_bytes = mint_commitment.compress().to_bytes().to_vec();

    // Witness 0: for ct-info-type (only output_type with mint commitment)
    let witness0 = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(mint_commitment_bytes)))
        .build();

    // Witness 1: for ct-token-type - INVALID mint commitment (31 bytes instead of 32)
    let invalid_mint_commitment = vec![0u8; 31]; // Wrong length!
    let witness1 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(invalid_mint_commitment)))
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness0.as_bytes().pack(), witness1.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert_script_error(result, ct_token_error::INVALID_MINT_COMMITMENT);
    println!("test_ct_token_invalid_mint_commitment_length: passed (correctly rejected)");
}

#[test]
fn test_ct_token_invalid_mint_commitment_point() {
    // Test: Mint commitment is 32 bytes but not a valid Ristretto point
    let mut context = Context::default();

    let ct_token_out_point = context.deploy_cell_by_name("ct-token-type");
    let ct_info_out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let ct_info_type_script = context
        .build_script(&ct_info_out_point, Bytes::from(vec![0u8; 33]))
        .unwrap();
    let ct_info_code_hash: [u8; 32] = ct_info_type_script.code_hash().unpack();

    let type_script = context
        .build_script(&ct_token_out_point, Bytes::from(ct_info_code_hash.to_vec()))
        .unwrap();

    let token_id = [44u8; 32];
    let mut ct_info_args = Vec::new();
    ct_info_args.extend_from_slice(&token_id);
    ct_info_args.push(0);
    let ct_info_script = context
        .build_script(&ct_info_out_point, ct_info_args.into())
        .unwrap();

    let old_supply = 0u128;
    let new_supply = 100u128;

    let ct_info_input_data = create_ct_info_data(old_supply, 1_000_000, MINTABLE);
    let ct_info_output_data = create_ct_info_data(new_supply, 1_000_000, MINTABLE);

    let ct_info_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script.clone()))
            .build(),
        ct_info_input_data,
    );
    let ct_info_input = CellInput::new_builder()
        .previous_output(ct_info_input_out_point)
        .build();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    let v_in = Scalar::from(0u64);
    let r_in = Scalar::random(&mut rng);
    let c_in = pc_gens.commit(v_in, r_in);
    let mut ct_token_input_data = c_in.compress().to_bytes().to_vec();
    ct_token_input_data.extend_from_slice(&[0u8; 32]);

    let ct_token_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        ct_token_input_data.into(),
    );
    let ct_token_input = CellInput::new_builder()
        .previous_output(ct_token_input_out_point)
        .build();

    let minted_amount = new_supply - old_supply;
    let mint_scalar = Scalar::from(minted_amount as u64);
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);

    let r_out = r_in;
    let v_out = Scalar::from(minted_amount as u64);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut ct_token_output_data = c_out.compress().to_bytes().to_vec();
    ct_token_output_data.extend_from_slice(&[0u8; 32]);

    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[minted_amount as u64],
        &[r_out],
        32,
        &mut rng,
    )
    .unwrap();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script))
            .build(),
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![
        CellDep::new_builder().out_point(ct_info_out_point).build(),
        CellDep::new_builder().out_point(ct_token_out_point).build(),
    ]
    .pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(ct_info_input)
        .input(ct_token_input)
        .outputs(outputs)
        .outputs_data(vec![ct_info_output_data, Bytes::from(ct_token_output_data)].pack())
        .build();

    let tx = context.complete_tx(tx);

    let mint_commitment_bytes = mint_commitment.compress().to_bytes().to_vec();

    let witness0 = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(mint_commitment_bytes)))
        .build();

    // Witness 1: INVALID Ristretto point (32 bytes of 0xFF)
    let invalid_mint_commitment = vec![0xFF; 32]; // Not a valid Ristretto point
    let witness1 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(invalid_mint_commitment)))
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness0.as_bytes().pack(), witness1.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert_script_error(result, ct_token_error::INVALID_MINT_COMMITMENT);
    println!("test_ct_token_invalid_mint_commitment_point: passed (correctly rejected)");
}

#[test]
fn test_ct_token_mint_commitment_sum_mismatch() {
    // Test: Mint commitment doesn't match the difference between output and input sums
    let mut context = Context::default();

    let ct_token_out_point = context.deploy_cell_by_name("ct-token-type");
    let ct_info_out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let ct_info_type_script = context
        .build_script(&ct_info_out_point, Bytes::from(vec![0u8; 33]))
        .unwrap();
    let ct_info_code_hash: [u8; 32] = ct_info_type_script.code_hash().unpack();

    let type_script = context
        .build_script(&ct_token_out_point, Bytes::from(ct_info_code_hash.to_vec()))
        .unwrap();

    let token_id = [45u8; 32];
    let mut ct_info_args = Vec::new();
    ct_info_args.extend_from_slice(&token_id);
    ct_info_args.push(0);
    let ct_info_script = context
        .build_script(&ct_info_out_point, ct_info_args.into())
        .unwrap();

    let old_supply = 0u128;
    let new_supply = 100u128;

    let ct_info_input_data = create_ct_info_data(old_supply, 1_000_000, MINTABLE);
    let ct_info_output_data = create_ct_info_data(new_supply, 1_000_000, MINTABLE);

    let ct_info_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script.clone()))
            .build(),
        ct_info_input_data,
    );
    let ct_info_input = CellInput::new_builder()
        .previous_output(ct_info_input_out_point)
        .build();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    let v_in = Scalar::from(0u64);
    let r_in = Scalar::random(&mut rng);
    let c_in = pc_gens.commit(v_in, r_in);
    let mut ct_token_input_data = c_in.compress().to_bytes().to_vec();
    ct_token_input_data.extend_from_slice(&[0u8; 32]);

    let ct_token_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        ct_token_input_data.into(),
    );
    let ct_token_input = CellInput::new_builder()
        .previous_output(ct_token_input_out_point)
        .build();

    let minted_amount = new_supply - old_supply;

    // Create output with 100 tokens
    let r_out = r_in;
    let v_out = Scalar::from(minted_amount as u64);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut ct_token_output_data = c_out.compress().to_bytes().to_vec();
    ct_token_output_data.extend_from_slice(&[0u8; 32]);

    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[minted_amount as u64],
        &[r_out],
        32,
        &mut rng,
    )
    .unwrap();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script))
            .build(),
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![
        CellDep::new_builder().out_point(ct_info_out_point).build(),
        CellDep::new_builder().out_point(ct_token_out_point).build(),
    ]
    .pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(ct_info_input)
        .input(ct_token_input)
        .outputs(outputs)
        .outputs_data(vec![ct_info_output_data, Bytes::from(ct_token_output_data)].pack())
        .build();

    let tx = context.complete_tx(tx);

    // WRONG mint commitment: 50 instead of 100
    let wrong_mint_scalar = Scalar::from(50u64);
    let wrong_mint_commitment = pc_gens.commit(wrong_mint_scalar, Scalar::ZERO);
    let wrong_mint_commitment_bytes = wrong_mint_commitment.compress().to_bytes().to_vec();

    let witness0 = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(wrong_mint_commitment_bytes.clone())))
        .build();

    // ct-token-type receives the wrong commitment
    let witness1 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(wrong_mint_commitment_bytes)))
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness0.as_bytes().pack(), witness1.as_bytes().pack()])
        .build();

    // Should fail at ct-info-type with InvalidMintCommitment, or at ct-token-type with InputOutputSumMismatch
    let result = context.verify_tx(&tx, 1_000_000_000);
    assert!(result.is_err(), "should fail with commitment sum mismatch");
    println!("test_ct_token_mint_commitment_sum_mismatch: passed (correctly rejected)");
}

// ============================================================================
// HIGH PRIORITY: ct-info-type Invalid Cell Count Tests
// ============================================================================

#[test]
fn test_ct_info_invalid_cell_count_2_inputs() {
    // Test: 2 inputs with ct-info-type should fail with InvalidCellCount
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let token_id = [50u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(100, 1_000_000, MINTABLE);

    // Create TWO inputs with the same type script
    let input_out_point1 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data.clone(),
    );
    let input1 = CellInput::new_builder()
        .previous_output(input_out_point1)
        .build();

    let input_out_point2 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data,
    );
    let input2 = CellInput::new_builder()
        .previous_output(input_out_point2)
        .build();

    let output_data = create_ct_info_data(200, 1_000_000, MINTABLE);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input1)
        .input(input2) // Second input with same type script!
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 20_000_000);
    assert_script_error(result, ct_info_error::INVALID_CELL_COUNT);
    println!("test_ct_info_invalid_cell_count_2_inputs: passed (correctly rejected)");
}

#[test]
fn test_ct_info_invalid_cell_count_0_outputs() {
    // Test: 1 input with 0 outputs should fail with InvalidCellCount
    // (This represents destroying the token info which is not allowed in mint flow)
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let token_id = [51u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(100, 1_000_000, MINTABLE);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // NO outputs with ct-info-type (create an output with different type)
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .build(), // No type script
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::new()].pack())
        .build();

    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 20_000_000);
    assert_script_error(result, ct_info_error::INVALID_CELL_COUNT);
    println!("test_ct_info_invalid_cell_count_0_outputs: passed (correctly rejected)");
}

#[test]
fn test_ct_info_genesis_multiple_outputs() {
    // Test: Genesis with 2 outputs should fail with InvalidCellCount
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Create a dummy input cell for Type ID calculation
    let dummy_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let dummy_input = CellInput::new_builder()
        .previous_output(dummy_input_out_point)
        .build();

    // Calculate Type ID (for output index 0)
    let type_id = calculate_type_id(&dummy_input, 0);
    let type_script = context
        .build_script(&out_point, Bytes::from(type_id.to_vec()))
        .unwrap();

    let output_data = create_ct_info_data(0, 1_000_000, MINTABLE);

    // Create TWO outputs with ct-info-type (should fail)
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .input(dummy_input)
        .outputs(outputs)
        .outputs_data(vec![output_data.clone(), output_data].pack())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 20_000_000);
    assert_script_error(result, ct_info_error::INVALID_CELL_COUNT);
    println!("test_ct_info_genesis_multiple_outputs: passed (correctly rejected)");
}

// ============================================================================
// MEDIUM PRIORITY: Malformed Range Proof Test
// ============================================================================

#[test]
fn test_ct_token_malformed_range_proof() {
    // Test: Random bytes that fail RangeProof::from_bytes
    let mut context = Context::default();
    let contract_out_point = context.deploy_cell_by_name("ct-token-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    let v = Scalar::from(100u64);
    let r = Scalar::random(&mut rng);
    let c = pc_gens.commit(v, r);
    let mut data = c.compress().to_bytes().to_vec();
    data.extend_from_slice(&[0u8; 32]);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        data.clone().into(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    // Random bytes that are NOT a valid RangeProof
    let malformed_proof = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
    let witness_args = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(malformed_proof)))
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert_script_error(result, ct_token_error::INVALID_RANGE_PROOF_WITNESS_FORMAT);
    println!("test_ct_token_malformed_range_proof: passed (correctly rejected)");
}

// ============================================================================
// MEDIUM PRIORITY: ct-info-type Additional Tests
// ============================================================================

#[test]
fn test_ct_info_unlimited_supply_cap() {
    // Test: supply_cap = 0 should allow unlimited minting (positive test)
    // NOTE: Authorization is handled by the lock script (always_success here), not type script
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let token_id = [53u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // supply_cap = 0 means unlimited
    let input_data = create_ct_info_data(0, 0, MINTABLE);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data,
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Mint a very large amount
    let old_supply = 0u128;
    let new_supply = 1_000_000_000_000u128; // 1 trillion tokens
    let output_data = create_ct_info_data(new_supply, 0, MINTABLE);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let cycles = context
        .verify_tx(&tx, 20_000_000)
        .expect("unlimited supply should pass");
    println!(
        "test_ct_info_unlimited_supply_cap: passed (minted 1T tokens), cycles: {}",
        cycles
    );
}

// NOTE: test_ct_info_invalid_signature_length has been removed.
// Signature verification is the responsibility of the LOCK SCRIPT, not the type script.

#[test]
fn test_ct_info_zero_mint_amount() {
    // Test: Trying to mint 0 tokens (new_supply == old_supply) should fail with InvalidMintAmount
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let token_id = [55u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let supply = 100u128;
    let input_data = create_ct_info_data(supply, 1_000_000, MINTABLE);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data,
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    // Same supply - trying to mint 0 tokens
    let output_data = create_ct_info_data(supply, 1_000_000, MINTABLE);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let mint_commitment = compute_mint_commitment(0);

    let witness_args = WitnessArgs::new_builder()
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert_script_error(result, ct_info_error::INVALID_MINT_AMOUNT);
    println!("test_ct_info_zero_mint_amount: passed (correctly rejected)");
}

#[test]
fn test_ct_info_missing_mint_commitment() {
    // Test: Mint without output_type in witness (missing mint commitment)
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let token_id = [56u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let old_supply = 0u128;
    let new_supply = 100u128;
    let input_data = create_ct_info_data(old_supply, 1_000_000, MINTABLE);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data,
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output_data = create_ct_info_data(new_supply, 1_000_000, MINTABLE);

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    // No output_type (mint commitment)!
    let witness_args = WitnessArgs::new_builder()
        // No output_type!
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert_script_error(result, ct_info_error::WITNESS_FORMAT_ERROR);
    println!("test_ct_info_missing_mint_commitment: passed (correctly rejected)");
}

#[test]
fn test_ct_info_data_wrong_length() {
    // Test: Cell data is not exactly 57 bytes should fail with InvalidDataLength
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("ct-info-type");
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Create a dummy input cell for Type ID calculation
    let dummy_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let dummy_input = CellInput::new_builder()
        .previous_output(dummy_input_out_point)
        .build();

    // Calculate Type ID
    let type_id = calculate_type_id(&dummy_input, 0);
    let type_script = context
        .build_script(&out_point, Bytes::from(type_id.to_vec()))
        .unwrap();

    // Wrong data length: 56 bytes instead of 57
    let invalid_data: Bytes = vec![0u8; 56].into();

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .type_(Some(type_script))
        .build()];

    let tx = TransactionBuilder::default()
        .input(dummy_input)
        .outputs(outputs)
        .outputs_data(vec![invalid_data].pack())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 20_000_000);
    assert_script_error(result, ct_info_error::INVALID_DATA_LENGTH);
    println!("test_ct_info_data_wrong_length: passed (correctly rejected)");
}
