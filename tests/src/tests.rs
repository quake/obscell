use crate::Loader;
use ckb_testtool::{
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};

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
