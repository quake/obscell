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

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

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

// generated unit test for contract ct-info-type
#[test]
fn test_ct_info_type() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ct-info-type");
    let out_point = context.deploy_cell(contract_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(vec![42]))
        .expect("script");

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500)
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500)
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, 10_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
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
