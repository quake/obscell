use ckb_gen_types::{packed::CellOutput, prelude::*};
use std::env;
use std::fs::{File, read};
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../ckb-auth/auth");

    let binary = read("../ckb-auth/auth").expect("read ckb-auth binary");
    let code_hash = CellOutput::calc_data_hash(&binary);

    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("ckb_auth_code_hash.rs");
    let mut out_file =
        BufWriter::new(File::create(out_path).expect("create ckb_auth_code_hash.rs"));

    writeln!(
        &mut out_file,
        "pub const CKB_AUTH_CODE_HASH: [u8; 32] = {:#02X?};",
        code_hash.as_slice()
    )
    .expect("write to ckb_auth_code_hash.rs");
}
