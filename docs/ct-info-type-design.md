# CT-Info-Type Design: Minting & Supply Tracking

## Overview

This document describes the design and implementation of the `ct-info-type` script for minting and supply tracking in the obscell confidential token system.

**Design Choice**: Approach A - Separate ct-info-type script with plain integer supply

**Key Properties**:
- Public supply tracking for auditability
- Confidential transfer amounts (via ct-token-type)
- On-chain verification, no external registries
- Issuer authorization via Ed25519 signatures
- Supply cap enforcement

## Architecture

### Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| `stealth-lock` | Hide recipients via stealth addresses (DONE) |
| `ct-token-type` | Hide amounts via Pedersen commitments + Bulletproofs (DONE) |
| `ct-info-type` | Track supply, authorize mints, enforce caps (NEW) |

### Design Rationale

**Why separate ct-info-type?**
- Clean separation of concerns
- No changes to working ct-token-type
- Explicit supply tracking in dedicated cell
- Easy to add governance features later

**Why plain integer supply?**
- Simpler implementation
- Easier auditing (supply is public)
- Minting is typically a privileged operation anyway
- Transfer amounts remain private

## Cell Layouts

### CT-Info-Type Cell

**Type Script Args (33 bytes)**:
```
Offset | Size | Field       | Description
-------|------|-------------|----------------------------------
0      | 32   | token_id    | Unique token identifier (immutable)
32     | 1    | version     | Protocol version (0 for v1)
```

**Cell Data (89 bytes)**:
```
Offset | Size | Field         | Description
-------|------|---------------|----------------------------------
0      | 16   | total_supply  | Current total supply (u128, little-endian)
16     | 32   | issuer_pubkey | Ed25519 public key (immutable)
48     | 16   | supply_cap    | Max supply, 0 = unlimited (immutable)
64     | 24   | reserved      | Reserved for future use (immutable after genesis)
88     | 1    | flags         | Bit flags (see below)
```

**Flags Bitfield**:
```rust
pub const MINTABLE: u8 = 0x01;  // Bit 0: Minting enabled
pub const BURNABLE: u8 = 0x02;  // Bit 1: Burning enabled (future)
pub const PAUSABLE: u8 = 0x04;  // Bit 2: Pausing enabled (future)
```

**Lock Script**: Any lock (typically ALWAYS_SUCCESS or issuer-controlled)

### CT-Token-Type Cell (No Changes)

**Cell Data (64 bytes)**:
```
Offset | Size | Field       | Description
-------|------|-------------|----------------------------------
0      | 32   | commitment  | Pedersen commitment C = vG + rH
32     | 32   | encrypted   | Encrypted amount data
```

**Type Script Args (32 bytes)**:
```
Offset | Size | Field     | Description
-------|------|-----------|----------------------------------
0      | 32   | token_id  | Must match ct-info-type token_id
```

## Validation Rules

### CT-Info-Type Script

#### Rule 1: Genesis Transaction
```
Condition: group_input_count == 0 (no ct-info-type inputs)

Requirements:
  - Exactly 1 ct-info-type output exists
  - issuer_pubkey != [0; 32]
  - flags & MINTABLE == MINTABLE
  - total_supply >= 0 (can start at 0 or premint)

Result: PASS (token created)
```

#### Rule 2: Mint Transaction
```
Condition: group_input_count == 1 AND group_output_count == 1

Load:
  input_cell = ct-info-type input[0]
  output_cell = ct-info-type output[0]

Immutability Checks:
  a) output.token_id == input.token_id
  b) output.issuer_pubkey == input.issuer_pubkey
  c) output.supply_cap == input.supply_cap
  d) output.reserved == input.reserved
  e) output.flags == input.flags

Mint Validation:
  f) input.flags & MINTABLE == MINTABLE
  g) minted_amount = output.total_supply - input.total_supply
  h) minted_amount > 0
  i) IF input.supply_cap > 0 THEN output.total_supply <= input.supply_cap
  j) No overflow: output.total_supply >= input.total_supply

Authorization:
  NOTE: Authorization is NOT handled by this type script.
  The lock script of the ct-info-type cell is responsible for verifying
  that the transaction is authorized (e.g., via issuer signature).
  This follows CKB's separation of concerns:
    - Lock script: WHO can spend the cell (authorization)
    - Type script: WHAT state transitions are valid (validation)

Mint Commitment:
  k) Compute mint_commitment = minted_amount * G + 0 * H
  l) Verify mint_commitment in witness.output_type matches expected value

Result: PASS if all checks succeed
```

#### Rule 3: Invalid Cases
```
FAIL if:
  - Multiple ct-info-type inputs (> 1)
  - Multiple ct-info-type outputs (> 1)
  - Input and output count don't match (not 1:1)
  - Immutable fields changed
  - Minting when MINTABLE flag not set
  - Supply exceeds cap
  - Arithmetic overflow
  - Invalid mint commitment
```

### CT-Token-Type Script (Modified)

#### Original Rule: Transfer
```
Condition: No mint commitment in witness

Validation:
  - sum(input_commitments) == sum(output_commitments)
  - Valid range proofs for all outputs

Result: PASS
```

#### New Rule: Mint Transfer
```
Condition: Mint commitment exists in witness.input_type

Load:
  mint_commitment = witness[0].input_type (32 bytes compressed Ristretto)

Validation:
  - sum(input_commitments) + mint_commitment == sum(output_commitments)
  - Valid range proofs for all outputs

Result: PASS
```

## Transaction Structures

### Genesis Transaction (Create Token)

**Purpose**: Initialize a new confidential token

**Structure**:
```
Inputs:  (any CKB cells for fees)

Outputs:
  [0] ct-info-type cell
      - Data: supply=0 (or premint), issuer_pubkey, cap, flags=MINTABLE
      - Type: ct-info-type script with unique token_id
      - Lock: Any

Cell Deps:
  - ct-info-type script code

Witnesses:
  - (none required for genesis)
```

**Example**:
```rust
// Create token with ID, issuer, cap of 1,000,000
let token_id = tx_hash;  // First tx hash as unique ID
let ct_info_data = CtInfoData {
    total_supply: 0,
    issuer_pubkey: issuer_ed25519_pubkey,
    supply_cap: 1_000_000,
    flags: MINTABLE,
    ..default()
};
```

### Mint Transaction (Pure Mint)

**Purpose**: Mint new tokens to fresh outputs

**Structure**:
```
Inputs:
  [0] ct-info-type cell (old supply)

Outputs:
  [0] ct-info-type cell (new supply = old + minted)
  [1..n] ct-token cells (sum of commitments = minted amount)

Cell Deps:
  - ct-info-type script code
  - ct-token-type script code

Witnesses:
  [0] WitnessArgs {
        input_type: issuer_signature (64 bytes Ed25519),
        output_type: mint_commitment (32 bytes compressed Ristretto)
      }
  [1] WitnessArgs {
        output_type: range_proof (Bulletproofs for new ct-tokens)
      }
```

**Example**:
```
Input ct-info: supply = 1000
Output ct-info: supply = 1100
Minted: 100

Output ct-tokens:
  [1] commitment C1 (amount ~60)
  [2] commitment C2 (amount ~40)

Validation:
  - ct-info-type: 1100 = 1000 + 100 ✓
  - ct-info-type: verify issuer signature ✓
  - ct-info-type: compute mint_commitment = 100*G + 0*H
  - ct-token-type: C1 + C2 = mint_commitment ✓
  - ct-token-type: verify range proofs for C1, C2 ✓
```

### Mint + Transfer Transaction

**Purpose**: Mint tokens and combine with existing balance

**Structure**:
```
Inputs:
  [0] ct-info-type cell (old supply)
  [1..m] ct-token cells (existing balance)

Outputs:
  [0] ct-info-type cell (new supply = old + minted)
  [1..n] ct-token cells (total = minted + existing balance)

Cell Deps:
  - ct-info-type script code
  - ct-token-type script code

Witnesses:
  [0] WitnessArgs {
        input_type: issuer_signature,
        output_type: mint_commitment
      }
  [1] WitnessArgs {
        output_type: range_proof
      }
```

**Example**:
```
Inputs:
  [0] ct-info: supply = 1000
  [1] ct-token: C_in (amount 50)

Outputs:
  [0] ct-info: supply = 1100
  [1] ct-token: C1 (amount 90)
  [2] ct-token: C2 (amount 60)

Validation:
  - ct-info-type: minted = 1100 - 1000 = 100 ✓
  - ct-info-type: mint_commitment = 100*G + 0*H
  - ct-token-type: C_in + mint_commitment = C1 + C2 ✓
  - This is equivalent to: C_in + 100*G = C1 + C2
  - Proves total outputs = 50 + 100 = 150 (split as 90 + 60)
```

## Cryptographic Details

### Mint Commitment Computation

**Goal**: Create a Pedersen commitment for the minted amount that ct-token-type can verify

**Approach**: Use known blinding factor (zero) for mint commitments

```rust
// In ct-info-type script
let pc_gens = PedersenGens::default();
let minted_amount = new_supply - old_supply;
let mint_blinding = Scalar::zero();  // Known blinding factor
let mint_commitment = pc_gens.commit(
    Scalar::from(minted_amount),
    mint_blinding
);

// Store in witness for ct-token-type
witness.output_type = Some(mint_commitment.compress().to_bytes());
```

**Why zero blinding?**
- Mint amounts are already public (in supply difference)
- Simplifies verification
- Recipients can re-blind when creating transfer commitments

### Authorization (Lock Script Responsibility)

**IMPORTANT**: Authorization is NOT handled by ct-info-type (type script).
Following CKB's design principles:
- **Lock script**: Verifies WHO can spend a cell (authorization)
- **Type script**: Verifies WHAT state transitions are valid (validation)

The ct-info-type cell's lock script is responsible for ensuring only
authorized parties (e.g., the issuer) can mint new tokens.

**Recommended Lock Script Implementation**:

For production use, choose a battle-tested lock script that has been deployed
and verified on CKB mainnet. The CKB ecosystem provides several production-ready
lock scripts with different authorization mechanisms.

**Key Requirements**:
- Must verify that only authorized parties can spend the ct-info-type cell
- Should be well-audited and production-proven on CKB mainnet
- Consider using existing lock scripts from the CKB ecosystem rather than
  implementing custom authorization logic

**WARNING**: Using ALWAYS_SUCCESS as lock script allows ANYONE to mint tokens.
This is only acceptable for testing purposes.

### Integration with CT-Token-Type

**Key Insight**: ct-token-type already validates sum of commitments. We just need to add mint_commitment to the input side.

**Modified Validation Logic**:
```rust
// Calculate sums
let input_sum: RistrettoPoint = sum(input_commitments);
let output_sum: RistrettoPoint = sum(output_commitments);

// Check for mint commitment
if let Some(mint_commitment_bytes) = witness[0].input_type {
    // Mint transaction
    let mint_commitment = decompress_ristretto(mint_commitment_bytes)?;
    
    if input_sum + mint_commitment != output_sum {
        return Err(Error::InputOutputSumMismatch);
    }
} else {
    // Regular transfer
    if input_sum != output_sum {
        return Err(Error::InputOutputSumMismatch);
    }
}

// Verify range proofs (unchanged)
verify_range_proofs(...)?;
```

## Security Analysis

### Threat Model

**Attacker Goals**:
1. Mint unlimited tokens
2. Exceed supply cap
3. Mint without authorization
4. Forge supply values
5. Break privacy of transfers

### Security Properties

**S1: Supply Integrity**
- Total supply stored in ct-info-type cell data (public)
- Supply updates validated by on-chain script
- Arithmetic checked for overflow
- Single ct-info-type cell enforces serialization

**S2: Authorization**
- Authorization is handled by the LOCK SCRIPT of ct-info-type cell
- Lock script verifies who can spend the cell (e.g., issuer signature)
- Type script only validates state transitions, not authorization
- This follows CKB's separation of concerns:
  - Lock script: WHO can spend (authorization)
  - Type script: WHAT transitions are valid (validation)
- Issuer pubkey stored in cell data for reference/auditability
- Recommended: Use a production-proven lock script from CKB ecosystem

**S3: Cap Enforcement**
- Supply cap immutable after genesis
- Every mint checks: new_supply <= cap
- Zero cap means unlimited (if desired)

**S4: Commitment Consistency**
- Mint commitment uses known blinding (zero)
- ct-token-type enforces: inputs + mint = outputs
- Range proofs prevent negative amounts
- Pedersen commitment binding property

**S5: Privacy Preservation**
- Mint amounts are public (supply delta)
- Transfer amounts remain private (commitments)
- Stealth addresses hide recipients
- Range proofs hide exact committed values

### Attack Scenarios

**Attack 1: Mint Without Updating ct-info-type**
```
Attempt: Create ct-token cells without ct-info-type input/output

Defense: ct-token-type requires mint_commitment in witness, which
         only ct-info-type can produce after validating supply increase
```

**Attack 2: Double Mint**
```
Attempt: Spend same ct-info-type cell in multiple transactions

Defense: CKB's UTXO model prevents double-spending of cells
```

**Attack 3: Exceed Supply Cap**
```
Attempt: Update ct-info-type with supply > cap

Defense: ct-info-type script checks: 
         IF cap > 0 THEN new_supply <= cap
```

**Attack 4: Unauthorized Mint**
```
Attempt: Mint without proper authorization

Defense: Lock script of ct-info-type cell handles authorization.
         The lock script must verify the transaction is authorized
         (e.g., by checking issuer signature). 
         
         IMPORTANT: If using ALWAYS_SUCCESS as lock script, anyone can mint!
         Production deployments MUST use a proper authorization lock script.
```

**Attack 5: Change Issuer**
```
Attempt: Replace issuer_pubkey to gain mint authority

Defense: ct-info-type enforces immutability:
         output.issuer_pubkey == input.issuer_pubkey
```

**Attack 6: Overflow Supply**
```
Attempt: Mint u128::MAX to wrap supply to zero

Defense: ct-info-type checks:
         output.total_supply >= input.total_supply
         new_supply - old_supply must not overflow
```

## Implementation Notes

### Data Structures

```rust
// ct-info-type/src/main.rs

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
        // Parse fields...
    }
    
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        // Serialize fields...
    }
}

pub mod flags {
    pub const MINTABLE: u8 = 0x01;
    pub const BURNABLE: u8 = 0x02;
    pub const PAUSABLE: u8 = 0x04;
}
```

### Dependencies

**New dependencies for ct-info-type**:
```toml
[dependencies]
ed25519-dalek = { version = "2", default-features = false }
curve25519-dalek = { version = "4", default-features = false }
```

**Modified dependencies for ct-token-type**:
```toml
# No new dependencies, just code changes
```

### Error Codes

```rust
// ct-info-type errors
#[repr(i8)]
pub enum Error {
    // System errors (1-4)
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    
    // ct-info-type errors (5-20)
    InvalidDataLength = 5,
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
```

```rust
// ct-token-type new errors
#[repr(i8)]
pub enum Error {
    // Existing errors (1-5)
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    InvalidInput,
    InvalidOutput,
    InputOutputSumMismatch,
    InvalidRangeProofWitnessFormat,
    InvalidRangeProof,
    
    // New mint-related error (10)
    InvalidMintCommitment = 10,
}
```

### Cycle Budget

**Estimated cycles**:
- ct-info-type validation: ~5-10M cycles
  - Cell data parsing: ~100K
  - Signature verification: ~5M (Ed25519)
  - Mint commitment computation: ~2M
  
- ct-token-type validation: ~500M-1B cycles (unchanged)
  - Commitment arithmetic: ~5M
  - Range proof verification: ~500M-1B (Bulletproofs)

**Test cycle limits**:
```rust
// For ct-info-type tests
context.verify_tx(&tx, 20_000_000)?;

// For ct-token-type tests (unchanged)
context.verify_tx(&tx, 1_000_000_000)?;

// For integration tests
context.verify_tx(&tx, 1_000_000_000)?;
```

## Testing Strategy

### Unit Tests (ct-info-type)

```rust
#[test]
fn test_genesis() {
    // Create first ct-info-type cell
    // Verify: accepts valid genesis
}

#[test]
fn test_mint_basic() {
    // Mint 100 tokens
    // Verify: supply updated correctly
}

#[test]
fn test_mint_with_cap() {
    // Create token with cap = 1000
    // Mint 500, then 500
    // Verify: both succeed
}

#[test]
fn test_mint_exceed_cap() {
    // Create token with cap = 1000
    // Try to mint 1001
    // Verify: fails
}

#[test]
fn test_mint_without_signature() {
    // Try to mint without issuer signature
    // Verify: fails
}

#[test]
fn test_mint_wrong_signature() {
    // Try to mint with different key's signature
    // Verify: fails
}

#[test]
fn test_immutable_issuer() {
    // Try to change issuer_pubkey
    // Verify: fails
}

#[test]
fn test_immutable_cap() {
    // Try to change supply_cap
    // Verify: fails
}

#[test]
fn test_mint_disabled() {
    // Create token with MINTABLE = false
    // Try to mint
    // Verify: fails
}

#[test]
fn test_supply_overflow() {
    // Set supply near u128::MAX
    // Try to mint more
    // Verify: fails
}
```

### Integration Tests

```rust
#[test]
fn test_mint_integration() {
    // Deploy ct-info-type + ct-token-type
    // Genesis ct-info cell
    // Mint transaction with ct-token outputs
    // Verify: all scripts pass
}

#[test]
fn test_mint_and_transfer() {
    // Mint tokens
    // Transfer them to another address
    // Verify: both transactions work
}

#[test]
fn test_multiple_mints() {
    // Mint 100 tokens (supply: 0 -> 100)
    // Mint 200 tokens (supply: 100 -> 300)
    // Mint 300 tokens (supply: 300 -> 600)
    // Verify: supply tracking correct
}

#[test]
fn test_mint_with_stealth() {
    // Mint tokens to stealth addresses
    // Verify: privacy + supply tracking work together
}
```

## Future Extensions

### Burning
```rust
// Allow supply to decrease
if new_supply < old_supply {
    let burned = old_supply - new_supply;
    // Verify ct-token inputs > outputs
    // Check BURNABLE flag
}
```

### Pause/Unpause
```rust
// Add pause state tracking
pub struct CtInfoData {
    // ... existing fields
    pub paused: bool,  // If true, reject mints
}
```

### Multiple Issuers
```rust
// Replace single issuer with multi-sig or threshold scheme
pub struct CtInfoData {
    // ... existing fields
    pub issuers: Vec<[u8; 32]>,  // Multiple pubkeys
    pub threshold: u8,            // M-of-N required
}
```

### Governance
```rust
// Add time locks, voting, etc.
pub struct CtInfoData {
    // ... existing fields
    pub governance: GovernanceRules,
}
```

## References

- [Nervos CKB Documentation](https://docs.nervos.org/)
- [Pedersen Commitments](https://crypto.stanford.edu/~dabo/pubs/abstracts/aggreg.html)
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/)
- [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
- [Bitcoin Stealth Addresses](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki)

## Changelog

### v1 (2026-01-25)
- Initial design
- Plain integer supply tracking
- Ed25519 issuer authorization
- Mint commitment coordination
- Supply cap enforcement
