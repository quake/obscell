use crate::Loader;
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;

use ed25519_dalek::{Signature, Signer, SigningKey};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

// Error codes for stealth-lock
#[allow(dead_code)]
mod stealth_lock_error {
    pub const ARGS_LENGTH_NOT_ENOUGH: i8 = 5;
    pub const SIGNATURE_LENGTH_NOT_ENOUGH: i8 = 6;
    pub const AUTH_ERROR: i8 = 7;
}

// Error codes for ct-info-type
#[allow(dead_code)]
mod ct_info_error {
    pub const INVALID_DATA_LENGTH: i8 = 5;
    pub const INVALID_CELL_COUNT: i8 = 7;
    pub const IMMUTABLE_FIELD_CHANGED: i8 = 8;
    pub const MINTING_DISABLED: i8 = 9;
    pub const SUPPLY_CAP_EXCEEDED: i8 = 10;
    pub const INVALID_MINT_AMOUNT: i8 = 11;
    pub const INVALID_SIGNATURE: i8 = 13;
    pub const WITNESS_FORMAT_ERROR: i8 = 15;
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
    let loader = Loader::default();
    let contract_bin: Bytes = loader.load_binary("stealth-lock");
    let ckb_auth_bin = loader.load_binary("../../contracts/ckb-auth/auth");
    let contract_out_point = context.deploy_cell(contract_bin);
    let ckb_auth_out_point = context.deploy_cell(ckb_auth_bin);

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

#[test]
fn test_stealth_lock_invalid_signature_length() {
    // Test: Signature length is not 65 bytes (should fail with SignatureLengthNotEnough)
    let mut context = Context::default();
    let loader = Loader::default();
    let contract_bin: Bytes = loader.load_binary("stealth-lock");
    let ckb_auth_bin = loader.load_binary("../../contracts/ckb-auth/auth");
    let contract_out_point = context.deploy_cell(contract_bin);
    let ckb_auth_out_point = context.deploy_cell(ckb_auth_bin);

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
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script)
            .build(),
    ];

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
fn test_stealth_lock_invalid_args_length() {
    // Test: Script args length is not 53 bytes (should fail with ArgsLengthNotEnough)
    let mut context = Context::default();
    let loader = Loader::default();
    let contract_bin: Bytes = loader.load_binary("stealth-lock");
    let ckb_auth_bin = loader.load_binary("../../contracts/ckb-auth/auth");
    let contract_out_point = context.deploy_cell(contract_bin);
    let ckb_auth_out_point = context.deploy_cell(ckb_auth_bin);

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
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script)
            .build(),
    ];

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
fn test_stealth_lock_wrong_signature() {
    // Test: Wrong signature (signed with different key) should fail with AuthError
    let mut context = Context::default();
    let loader = Loader::default();
    let contract_bin: Bytes = loader.load_binary("stealth-lock");
    let ckb_auth_bin = loader.load_binary("../../contracts/ckb-auth/auth");
    let contract_out_point = context.deploy_cell(contract_bin);
    let ckb_auth_out_point = context.deploy_cell(ckb_auth_bin);

    let secp = Secp256k1::new();
    let mut rng = rand::rng();

    // Create lock with one keypair
    let seckey1 = SecretKey::new(&mut rng);
    let pubkey1 = PublicKey::from_secret_key(&secp, &seckey1);
    let public_key_hash = blake2b_256(pubkey1.serialize())[0..20].to_vec();
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
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script)
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::new()].pack())
        .build();

    // Sign with a DIFFERENT key
    let seckey2 = SecretKey::new(&mut rng);
    let message =
        Message::from_digest(tx.hash().raw_data().to_vec().as_slice().try_into().unwrap());
    let (recovery_id, signature) = secp
        .sign_ecdsa_recoverable(message, &seckey2) // Wrong key!
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
fn test_stealth_lock_empty_witness() {
    // Test: Empty witness.lock should fail
    let mut context = Context::default();
    let loader = Loader::default();
    let contract_bin: Bytes = loader.load_binary("stealth-lock");
    let ckb_auth_bin = loader.load_binary("../../contracts/ckb-auth/auth");
    let contract_out_point = context.deploy_cell(contract_bin);
    let ckb_auth_out_point = context.deploy_cell(ckb_auth_bin);

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
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(256)
            .lock(lock_script)
            .build(),
    ];

    // Empty witness - no lock field
    let witness_args = WitnessArgs::new_builder().build();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::new()].pack())
        .witness(witness_args.as_bytes())
        .build();

    let result = context.verify_tx(&tx, 10_000_000);
    assert!(result.is_err(), "should fail with empty witness");
    println!("test_stealth_lock_empty_witness: passed (correctly rejected)");
}

// Helper function to create ct-info-type cell data
fn create_ct_info_data(
    total_supply: u128,
    issuer_pubkey: &[u8; 32],
    supply_cap: u128,
    flags: u8,
) -> Bytes {
    let mut data = Vec::new();
    data.extend_from_slice(&total_supply.to_le_bytes()); // [0..16]
    data.extend_from_slice(issuer_pubkey); // [16..48]
    data.extend_from_slice(&supply_cap.to_le_bytes()); // [48..64]
    data.extend_from_slice(&[0u8; 24]); // [64..88] reserved
    data.push(flags); // [88]
    data.into()
}

// Helper function to compute mint commitment for a given amount
// mint_commitment = amount * G (with zero blinding factor)
fn compute_mint_commitment(amount: u128) -> Bytes {
    use bulletproofs::PedersenGens;
    let pc_gens = PedersenGens::default();
    let amount_scalar = Scalar::from(amount);
    // Commitment with zero blinding factor: amount * G + 0 * H = amount * G
    let commitment = pc_gens.commit(amount_scalar, Scalar::ZERO);
    Bytes::from(commitment.compress().to_bytes().to_vec())
}

const MINTABLE: u8 = 0x01;

#[test]
fn test_ct_info_genesis() {
    // Test: Create a new token (genesis transaction)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // Generate issuer keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    // Create token with supply_cap = 1,000,000
    let token_id = [1u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0); // version

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let output_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();
    let tx = context.complete_tx(tx);

    let cycles = context
        .verify_tx(&tx, 20_000_000)
        .expect("genesis should pass");
    println!("ct-info genesis consume cycles: {}", cycles);
}

#[test]
fn test_ct_info_mint_basic() {
    // Test: Mint tokens (supply 0 -> 100)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // Generate issuer keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    // Create token
    let token_id = [2u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Mint 100 tokens
    let old_supply = 0u128;
    let new_supply = 100u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    // Add cell deps
    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    // Sign the transaction (must be after complete_tx to get correct tx_hash)
    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Compute mint commitment for the minted amount
    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let cycles = context
        .verify_tx(&tx, 20_000_000)
        .expect("mint should pass");
    println!("ct-info mint basic consume cycles: {}", cycles);
}

#[test]
fn test_ct_info_mint_exceed_cap() {
    // Test: Try to mint beyond supply cap (should fail)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    let token_id = [3u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Create token with cap = 1000
    let supply_cap = 1000u128;
    let input_data = create_ct_info_data(0, &issuer_pubkey, supply_cap, MINTABLE);

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

    // Try to mint 1001 tokens (exceeds cap)
    let old_supply = 0u128;
    let new_supply = 1001u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, supply_cap, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    // Add cell deps
    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Compute mint commitment for the minted amount
    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    // Should fail with SupplyCapExceeded
    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail when exceeding cap");
}

#[test]
fn test_ct_info_mint_without_signature() {
    // Test: Try to mint without valid signature (should fail)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    let token_id = [4u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    let output_data = create_ct_info_data(100, &issuer_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    // Add cell deps
    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    // No signature provided
    let tx = context.complete_tx(tx);

    // Should fail with WitnessFormatError or InvalidSignature
    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail without signature");
}

#[test]
fn test_ct_info_immutable_issuer_pubkey() {
    // Test: Changing issuer_pubkey should fail with ImmutableFieldChanged
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    // Generate a different pubkey for output
    let signing_key2 = SigningKey::generate(&mut csprng);
    let different_pubkey: [u8; 32] = signing_key2.verifying_key().to_bytes();

    let token_id = [5u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Try to change issuer_pubkey in output
    let old_supply = 0u128;
    let new_supply = 100u128;
    let output_data = create_ct_info_data(new_supply, &different_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Compute mint commitment for the minted amount
    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail when issuer_pubkey is changed");
    println!("test_ct_info_immutable_issuer_pubkey: passed (correctly rejected)");
}

#[test]
fn test_ct_info_immutable_supply_cap() {
    // Test: Changing supply_cap should fail with ImmutableFieldChanged
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    let token_id = [6u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Try to change supply_cap from 1_000_000 to 2_000_000
    let old_supply = 0u128;
    let new_supply = 100u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, 2_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Compute mint commitment for the minted amount
    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail when supply_cap is changed");
    println!("test_ct_info_immutable_supply_cap: passed (correctly rejected)");
}

#[test]
fn test_ct_info_immutable_flags() {
    // Test: Changing flags should fail with ImmutableFieldChanged
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    let token_id = [7u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Try to change flags from MINTABLE (0x01) to MINTABLE|BURNABLE (0x03)
    let old_supply = 0u128;
    let new_supply = 100u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, 1_000_000, 0x03);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Compute mint commitment for the minted amount
    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail when flags are changed");
    println!("test_ct_info_immutable_flags: passed (correctly rejected)");
}

#[test]
fn test_ct_info_decrease_supply() {
    // Test: Decreasing total_supply should fail with InvalidMintAmount
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    let token_id = [8u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Start with supply = 100
    let input_data = create_ct_info_data(100, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Try to decrease supply from 100 to 50
    let old_supply = 100u128;
    let new_supply = 50u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Use dummy mint_commitment since this test fails before reaching mint_commitment validation
    // (fails at InvalidMintAmount check because new_supply < old_supply)
    let mint_commitment = compute_mint_commitment(0);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail when supply is decreased");
    println!("test_ct_info_decrease_supply: passed (correctly rejected)");
}

#[test]
fn test_ct_info_wrong_signature_key() {
    // Test: Using wrong private key for signature should fail with InvalidSignature
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;

    // Generate issuer keypair (used in cell data)
    let signing_key1 = SigningKey::generate(&mut csprng);
    let issuer_pubkey: [u8; 32] = signing_key1.verifying_key().to_bytes();

    // Generate a DIFFERENT keypair for signing
    let signing_key2 = SigningKey::generate(&mut csprng);

    let token_id = [9u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    let old_supply = 0u128;
    let new_supply = 100u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());

    // Sign with WRONG key
    let signature: Signature = signing_key2.sign(&message);

    // Compute mint commitment for the minted amount
    let minted_amount = new_supply - old_supply;
    let mint_commitment = compute_mint_commitment(minted_amount);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail with wrong signature key");
    println!("test_ct_info_wrong_signature_key: passed (correctly rejected)");
}

#[test]
fn test_ct_info_genesis_zero_issuer() {
    // Test: Genesis with all-zero issuer_pubkey should fail
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let zero_pubkey = [0u8; 32];

    let token_id = [10u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let output_data = create_ct_info_data(0, &zero_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail with zero issuer_pubkey");
    println!("test_ct_info_genesis_zero_issuer: passed (correctly rejected)");
}

#[test]
fn test_ct_info_genesis_not_mintable() {
    // Test: Genesis without MINTABLE flag should fail
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let issuer_pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

    let token_id = [11u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    // Create with flags = 0 (no MINTABLE)
    let output_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, 0);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail without MINTABLE flag");
    println!("test_ct_info_genesis_not_mintable: passed (correctly rejected)");
}

#[test]
fn test_ct_info_invalid_mint_commitment() {
    // Test: Mint with wrong mint_commitment should fail with InvalidMintCommitment
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey: [u8; 32] = verifying_key.to_bytes();

    let token_id = [12u8; 32];
    let mut type_args = Vec::new();
    type_args.extend_from_slice(&token_id);
    type_args.push(0);

    let type_script = context.build_script(&out_point, type_args.into()).unwrap();

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let input_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Mint 100 tokens
    let old_supply = 0u128;
    let new_supply = 100u128;
    let output_data = create_ct_info_data(new_supply, &issuer_pubkey, 1_000_000, MINTABLE);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let cell_deps = vec![CellDep::new_builder().out_point(out_point).build()].pack();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![output_data].pack())
        .build();

    let tx = context.complete_tx(tx);

    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Use WRONG mint_commitment (50 instead of 100)
    let wrong_mint_commitment = compute_mint_commitment(50);

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(wrong_mint_commitment))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    let result = context.verify_tx(&tx, 20_000_000);
    assert!(result.is_err(), "should fail with wrong mint_commitment");
    println!("test_ct_info_invalid_mint_commitment: passed (correctly rejected)");
}

#[test]
fn test_ct_token_type() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-token-type");
    let contract_out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    // prepare cells
    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    let v_in1 = Scalar::from(60u64);
    let r_in1 = Scalar::random(&mut rng);
    let c_in1: RistrettoPoint = pc_gens.commit(v_in1, r_in1);
    let mut input_data1 = c_in1.compress().to_bytes().to_vec();
    input_data1.extend_from_slice(&[0u8; 32]);

    let v_in2 = Scalar::from(40u64);
    let r_in2 = Scalar::random(&mut rng);
    let c_in2 = pc_gens.commit(v_in2, r_in2);
    let mut input_data2 = c_in2.compress().to_bytes().to_vec();
    input_data2.extend_from_slice(&[0u8; 32]);

    let input_out_point1 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        input_data1.into(),
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
        input_data2.into(),
    );
    let input2 = CellInput::new_builder()
        .previous_output(input_out_point2)
        .build();

    let sum_r_in = r_in1 + r_in2;
    let r_out1 = Scalar::random(&mut rng);
    let r_out2 = sum_r_in - r_out1;

    let bp_gens = BulletproofGens::new(64, 2);
    let mut prover_transcript = Transcript::new(b"ct-token-type");

    let (proof, commitments) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[55, 45],
        &[r_out1, r_out2],
        32,
        &mut rng,
    )
    .unwrap();

    let witness_args = WitnessArgs::new_builder()
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let mut output_data1 = commitments[0].to_bytes().to_vec();
    output_data1.extend_from_slice(&[0u8; 32]);

    let mut output_data2 = commitments[1].to_bytes().to_vec();
    output_data2.extend_from_slice(&[0u8; 32]);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()))
            .build(),
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script.clone()))
            .build(),
    ];

    let outputs_data: Vec<Bytes> = vec![output_data1.into(), output_data2.into()];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input1)
        .input(input2)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, 1_000_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_ct_token_invalid_input_length() {
    // Test: Input cell data is not 64 bytes (should fail with InvalidInput)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-token-type");
    let contract_out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    // Create input with wrong data length (32 bytes instead of 64)
    let invalid_input_data = vec![0u8; 32];

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

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

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
    assert!(result.is_err(), "should fail with invalid input length");
    println!("test_ct_token_invalid_input_length: passed (correctly rejected)");
}

#[test]
fn test_ct_token_invalid_output_length() {
    // Test: Output cell data is not 64 bytes (should fail with InvalidOutput)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-token-type");
    let contract_out_point = context.deploy_cell(contract_bin);
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

    // Invalid output - only 32 bytes
    let invalid_output_data = vec![0u8; 32];

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(invalid_output_data)].pack())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert!(result.is_err(), "should fail with invalid output length");
    println!("test_ct_token_invalid_output_length: passed (correctly rejected)");
}

#[test]
fn test_ct_token_commitment_mismatch() {
    // Test: Input and output commitment sums don't match (should fail with InputOutputSumMismatch)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-token-type");
    let contract_out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    // Input: 100 tokens with random blinding factor
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

    // Output: 50 tokens with DIFFERENT blinding factor (not matching input)
    let v_out = Scalar::from(50u64);
    let r_out = Scalar::random(&mut rng); // Different r, causes mismatch
    let c_out = pc_gens.commit(v_out, r_out);
    let mut output_data = c_out.compress().to_bytes().to_vec();
    output_data.extend_from_slice(&[0u8; 32]);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let (proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[50],
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
    assert!(result.is_err(), "should fail with commitment mismatch");
    println!("test_ct_token_commitment_mismatch: passed (correctly rejected)");
}

#[test]
fn test_ct_token_invalid_range_proof() {
    // Test: Invalid range proof (proof doesn't match commitments)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-token-type");
    let contract_out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    let lock_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .unwrap();

    let type_script = context
        .build_script(&contract_out_point, Bytes::from(vec![0]))
        .unwrap();

    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    // Input
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

    // Output with correct blinding factor sum
    let r_out = r_in; // Same r to make commitment sum match
    let v_out = Scalar::from(100u64);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut output_data = c_out.compress().to_bytes().to_vec();
    output_data.extend_from_slice(&[0u8; 32]);

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    // Create a proof for DIFFERENT values (wrong proof)
    let bp_gens = BulletproofGens::new(64, 1);
    let mut prover_transcript = Transcript::new(b"ct-token-type");
    let wrong_r = Scalar::random(&mut rng);
    let (wrong_proof, _) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[50], // Wrong value
        &[wrong_r],
        32,
        &mut rng,
    )
    .unwrap();

    let witness_args = WitnessArgs::new_builder()
        .output_type(Some(wrong_proof.to_bytes().pack()))
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(output_data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert!(result.is_err(), "should fail with invalid range proof");
    println!("test_ct_token_invalid_range_proof: passed (correctly rejected)");
}

#[test]
fn test_ct_token_missing_range_proof() {
    // Test: Missing range proof in witness (should fail with InvalidRangeProofWitnessFormat)
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-token-type");
    let contract_out_point = context.deploy_cell(contract_bin);
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

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    // No range proof in witness
    let witness_args = WitnessArgs::new_builder().build();

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(vec![Bytes::from(data)].pack())
        .witness(witness_args.as_bytes())
        .build();
    let tx = context.complete_tx(tx);

    let result = context.verify_tx(&tx, 1_000_000_000);
    assert!(result.is_err(), "should fail with missing range proof");
    println!("test_ct_token_missing_range_proof: passed (correctly rejected)");
}

#[test]
fn test_ct_token_mint_with_commitment() {
    // Test: Mint transaction with mint_commitment in witness and ct-info-type present
    let mut context = Context::default();
    let loader = Loader::default();

    // Deploy contracts
    let ct_token_bin: Bytes = loader.load_binary("ct-token-type");
    let ct_info_bin: Bytes = loader.load_binary("ct-info-type");
    let ct_token_out_point = context.deploy_cell(ct_token_bin);
    let ct_info_out_point = context.deploy_cell(ct_info_bin);
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

    // Generate issuer keypair for ct-info-type
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let issuer_pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

    // Create ct-info-type cell (input)
    let token_id = [42u8; 32];
    let mut ct_info_args = Vec::new();
    ct_info_args.extend_from_slice(&token_id);
    ct_info_args.push(0); // version
    let ct_info_script = context
        .build_script(&ct_info_out_point, ct_info_args.into())
        .unwrap();

    let old_supply = 0u128;
    let new_supply = 100u128;
    let minted_amount = new_supply - old_supply;

    let ct_info_input_data = create_ct_info_data(old_supply, &issuer_pubkey, 1_000_000, MINTABLE);
    let ct_info_output_data = create_ct_info_data(new_supply, &issuer_pubkey, 1_000_000, MINTABLE);

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

    // Create ct-token-type cells
    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;

    // Create a "zero" input cell to satisfy group input requirement
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

    // Mint commitment uses zero blinding factor (public amount)
    let mint_scalar = Scalar::from(minted_amount as u64);
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);

    // Output: minted tokens
    // r_out must equal r_in + 0 (since mint uses zero blinding)
    let r_out = r_in;
    let v_out = Scalar::from(minted_amount as u64);
    let c_out = pc_gens.commit(v_out, r_out);
    let mut ct_token_output_data = c_out.compress().to_bytes().to_vec();
    ct_token_output_data.extend_from_slice(&[0u8; 32]);

    // Create range proof for output
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

    // Build outputs
    let outputs = vec![
        // ct-info-type output
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .type_(Some(ct_info_script))
            .build(),
        // ct-token-type output
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

    // Cell deps
    let cell_deps = vec![
        CellDep::new_builder().out_point(ct_info_out_point).build(),
        CellDep::new_builder().out_point(ct_token_out_point).build(),
    ]
    .pack();

    // Build transaction
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(ct_info_input) // ct-info-type input first
        .input(ct_token_input) // ct-token-type input second
        .outputs(outputs)
        .outputs_data(vec![ct_info_output_data, Bytes::from(ct_token_output_data)].pack())
        .build();

    let tx = context.complete_tx(tx);

    // Sign the ct-info-type transaction
    let tx_hash = tx.hash().raw_data();
    let mut message = Vec::new();
    message.extend_from_slice(&tx_hash);
    message.extend_from_slice(&old_supply.to_le_bytes());
    message.extend_from_slice(&new_supply.to_le_bytes());
    let signature: Signature = signing_key.sign(&message);

    // Compute mint commitment for witness
    let mint_commitment_bytes = mint_commitment.compress().to_bytes().to_vec();

    // Witness 0: for ct-info-type input
    // input_type: issuer signature (64 bytes)
    // output_type: mint_commitment (32 bytes)
    let witness0 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(signature.to_bytes().to_vec())))
        .output_type(Some(Bytes::from(mint_commitment_bytes.clone())))
        .build();

    // Witness 1: for ct-token-type input
    // input_type: mint_commitment (32 bytes) - ct-token-type reads this
    // output_type: range_proof - ct-token-type reads this
    let witness1 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(mint_commitment_bytes)))
        .output_type(Some(proof.to_bytes().pack()))
        .build();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness0.as_bytes().pack(), witness1.as_bytes().pack()])
        .build();

    let cycles = context
        .verify_tx(&tx, 1_000_000_000)
        .expect("mint transaction should pass");
    println!(
        "test_ct_token_mint_with_commitment consume cycles: {}",
        cycles
    );
}

#[test]
fn test_ct_token_mint_without_ct_info_type() {
    // Test: Mint transaction with mint_commitment but WITHOUT ct-info-type should fail
    // This tests the security fix that prevents unauthorized minting
    let mut context = Context::default();
    let loader = Loader::default();

    // Deploy only ct-token-type (not ct-info-type in the transaction inputs)
    let ct_token_bin: Bytes = loader.load_binary("ct-token-type");
    let ct_info_bin: Bytes = loader.load_binary("ct-info-type");
    let ct_token_out_point = context.deploy_cell(ct_token_bin);
    let ct_info_out_point = context.deploy_cell(ct_info_bin);
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

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

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
    let loader = Loader::default();

    let ct_token_bin: Bytes = loader.load_binary("ct-token-type");
    let ct_token_out_point = context.deploy_cell(ct_token_bin);
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

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script)
            .type_(Some(type_script))
            .build(),
    ];

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
