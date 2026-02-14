# AGENTS.md - Coding Agent Guide for obscell

This guide provides coding agents with essential information about the obscell codebase - a privacy-preserving token system on Nervos CKB combining stealth addresses and confidential transactions using Bulletproofs.

## Project Overview

- **Language**: Rust (Edition 2024, Nightly 1.94.0+)
- **Platform**: Nervos CKB Smart Contracts (RISC-V `riscv64imac-unknown-none-elf`)
- **Architecture**: Three smart contract scripts:
  - `stealth-lock`: Stealth address lock script (hides recipients)
  - `ct-token-type`: Confidential token validation (hides amounts)
  - `ct-info-type`: Token issuance management
- **Environment**: `no_std` embedded environment with custom allocator
- **Status**: Work in progress, not ready for release

## Build Commands

### Setup
```bash
make prepare              # Install RISC-V target (run once)
```

### Build
```bash
make                      # Default: build + test
make build                # Build all contracts for RISC-V
make build CONTRACT=stealth-lock  # Build specific contract
MODE=debug make build     # Build in debug mode (default: release)
```

### Testing
```bash
make test                 # Run all tests
cargo test                # Run tests directly
make test CARGO_ARGS="-- --nocapture"  # Show stdout
cargo test test_stealth_lock  # Run single test by name
cargo test -- --test-threads=1  # Run tests serially
MODE=debug make test      # Test debug builds
```

### Linting & Formatting
```bash
make check                # Run cargo check
make clippy               # Run cargo clippy
make fmt                  # Format code with rustfmt
```

### Other Commands
```bash
make clean                # Clean build artifacts
make checksum             # Generate checksums for reproducible builds
```

## Code Style Guidelines

### File Structure & Attributes
All contract entry points must use:
```rust
#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);

#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);  // 16KB fixed, 1.2MB dynamic, 64B min block
```

### Import Organization
```rust
// Standard imports first
use alloc::vec::Vec;
use core::result::Result;

// External crate imports (alphabetical)
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{load_script, load_witness_args},
};

// Local imports last
use crate::error::Error;
```

### Naming Conventions
- **Contracts**: kebab-case (`stealth-lock`, `ct-token-type`)
- **Functions**: snake_case (`program_entry`, `load_witness_args`)
- **Types/Enums**: PascalCase (`Error`, `TxHashRng`)
- **Constants**: SCREAMING_SNAKE_CASE (`CKB_AUTH_CODE_HASH`)
- **Variables**: snake_case (`pubkey_hash`, `script_args`)

### Error Handling
Define custom error enums as `i8` repr and implement `From<SysError>`:
```rust
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Custom errors...
    InvalidInput,
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
```

Use `Result<T, Error>` for all fallible operations. The entry point returns `i8`:
```rust
pub fn program_entry() -> i8 {
    match validate() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}
```

### Type Usage
- Always use explicit types for cryptographic primitives
- Use `alloc::vec::Vec` instead of `std::vec::Vec` (no_std)
- Prefer `&[u8]` for byte slices
- Use CKB types: `Source`, `CellOutput`, `WitnessArgs`, `Script`
- Crypto types: `RistrettoPoint`, `Scalar`, `CompressedRistretto`

### Memory & Performance
- **No dynamic allocation in hot paths** - pre-allocate when possible
- **Fixed heap**: 16KB, **Dynamic heap**: ~1.2MB, **Min block**: 64 bytes
- **Cycle limits**: Small tests use ~10M cycles, complex crypto uses up to 1B cycles
- **Always report cycles consumed** in tests via `println!("consume cycles: {}", cycles)`

### Testing Patterns
Structure tests as: Deploy → Prepare → Build TX → Verify
```rust
#[test]
fn test_contract_name() {
    // 1. Deploy contract
    let mut context = Context::default();
    let contract_bin = Loader::default().load_binary("contract-name");
    let out_point = context.deploy_cell(contract_bin);
    
    // 2. Prepare scripts and cells
    let lock_script = context.build_script(&out_point, args).unwrap();
    
    // 3. Build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .build();
    
    // 4. Verify and report cycles
    let cycles = context.verify_tx(&tx, 10_000_000).expect("pass verification");
    println!("consume cycles: {}", cycles);
}
```

### Build-time Code Generation
Use `build.rs` for generating constants:
```rust
// build.rs
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../path/to/dependency");
    
    // Generate code at build time
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated.rs");
    let mut f = File::create(&dest_path).unwrap();
    writeln!(&mut f, "pub const FOO: u32 = {};", value).unwrap();
}
```

Include in main contract:
```rust
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
```

## Documentation Standards
- Use `///` for public API documentation
- Use `//` for inline comments
- Document complex cryptographic operations with references
- Include cycle consumption in test outputs
- Document fixed data layouts (e.g., "Cell data: >= 32 bytes, first 32B is commitment")

## Contract-Specific Notes

### Stealth Lock (`contracts/stealth-lock/`)
- Script args: 53 bytes (33B pubkey P + 20B pubkey hash)
- Uses `ckb-auth` for signature verification (prebuilt binary)
- Auth via `exec_cell` with algorithm ID, signature, message, pubkey hash

### CT Token Type (`contracts/ct-token-type/`)
- Cell data: >= 32 bytes (first 32B is compressed Ristretto commitment, rest is off-chain encrypted data)
- Validates Bulletproofs range proofs in witness data
- Uses Pedersen commitments for confidential amounts

### CT Info Type (`contracts/ct-info-type/`)
- Manages token issuance and supply tracking
- Cell data: 57 bytes (supply, cap, flags)

## Common Pitfalls
- ❌ Don't use `std` - this is `no_std` environment
- ❌ Don't use unbounded allocation - fixed heap limits apply
- ❌ Don't skip cycle reporting in tests
- ❌ Don't modify Cargo workspace structure without updating `@@INSERTION_POINT@@`
- ❌ Don't commit without running `make clippy` and `make test`
- ✅ Always verify transactions with appropriate cycle limits
- ✅ Use `default-features = false` for external dependencies
- ✅ Keep contract binaries small - RISC-V has size constraints

## Development Workflow
1. Edit contract source in `contracts/*/src/main.rs`
2. Build: `make build CONTRACT=<name>`
3. Write tests in `tests/src/tests.rs`
4. Test: `make test CARGO_ARGS="-- test_name"`
5. Lint: `make clippy`
6. Format: `make fmt`
7. Verify cycles and functionality

## Resources
- CKB Docs: https://docs.nervos.org/
- ckb-std API: https://docs.rs/ckb-std/
- Bulletproofs: https://crypto.stanford.edu/bulletproofs/
- Bitcoin Stealth Addresses: https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki
