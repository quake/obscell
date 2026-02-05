# Quick Reference: CT-Info-Type Usage

## Cell Data Format

### CT-Info-Type Cell (89 bytes)
```rust
struct CtInfoData {
    total_supply: u128,      // [0..16]   Current supply
    issuer_pubkey: [u8; 32], // [16..48]  Ed25519 public key
    supply_cap: u128,        // [48..64]  Max supply (0 = unlimited)
    reserved: [u8; 24],      // [64..88]  Reserved
    flags: u8,               // [88]      MINTABLE = 0x01
}
```

### Type Script Args (33 bytes)
```
[0..32]   token_id: [u8; 32]  // Unique token ID
[32]      version: u8          // Protocol version (0)
```

## Common Operations

### 1. Create Token (Genesis)
```rust
// No inputs, 1 ct-info-type output
let ct_info_data = create_ct_info_data(
    0,                    // initial supply
    &issuer_pubkey,       // Ed25519 public key
    1_000_000,            // supply cap (0 = unlimited)
    0x01,                 // MINTABLE flag
);

TransactionBuilder::default()
    .outputs(vec![ct_info_output])
    .outputs_data(vec![ct_info_data].pack())
    .build();
```

### 2. Mint Tokens
```rust
// 1 input (old ct-info), 1 output (new ct-info) + ct-token outputs
let old_supply = 1000u128;
let new_supply = 1100u128;
let minted = 100u128;

// Sign: tx_hash || old_supply || new_supply
let mut message = Vec::new();
message.extend_from_slice(&tx_hash);
message.extend_from_slice(&old_supply.to_le_bytes());
message.extend_from_slice(&new_supply.to_le_bytes());
let signature = issuer_key.sign(&message);

// Create mint commitment
let mint_commitment = minted * RISTRETTO_BASEPOINT_POINT;

// Witness
WitnessArgs::new_builder()
    .input_type(Some(signature.to_bytes().into()))  // 64 bytes
    .output_type(Some(mint_commitment.compress().to_bytes().into()))  // 32 bytes
    .build();
```

### 3. Verify Mint (Off-chain)
```rust
// Check supply update
assert_eq!(new_supply, old_supply + minted);

// Verify signature
let verifying_key = VerifyingKey::from_bytes(&issuer_pubkey)?;
verifying_key.verify(&message, &signature)?;

// Check cap
if supply_cap > 0 {
    assert!(new_supply <= supply_cap);
}

// Verify ct-token outputs sum to minted amount
assert_eq!(ct_token_commitments.sum(), mint_commitment);
```

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 5 | InvalidDataLength | Cell data != 89 bytes |
| 6 | InvalidArgsLength | Type args != 33 bytes |
| 7 | InvalidCellCount | Wrong number of inputs/outputs |
| 8 | ImmutableFieldChanged | Changed issuer/cap/flags |
| 9 | MintingDisabled | MINTABLE flag not set |
| 10 | SupplyCapExceeded | new_supply > cap |
| 11 | InvalidMintAmount | minted <= 0 |
| 12 | SupplyOverflow | Arithmetic overflow |
| 13 | InvalidSignature | Bad Ed25519 signature |
| 14 | InvalidMintCommitment | Bad mint commitment |
| 15 | WitnessFormatError | Missing witness data |

## Validation Rules

### Genesis (0 inputs → 1 output)
- ✓ issuer_pubkey != [0; 32]
- ✓ flags & MINTABLE == 0x01

### Mint (1 input → 1 output)
- ✓ token_id unchanged
- ✓ issuer_pubkey unchanged
- ✓ supply_cap unchanged
- ✓ flags unchanged
- ✓ minted = new_supply - old_supply > 0
- ✓ new_supply <= cap (if cap > 0)
- ✓ Valid Ed25519 signature

## Integration with CT-Token-Type

### Regular Transfer (no mint)
```
ct-token-type validates:
  sum(input_commitments) == sum(output_commitments)
```

### Mint Transfer (with mint)
```
ct-token-type validates:
  sum(input_commitments) + mint_commitment == sum(output_commitments)
  
Where mint_commitment comes from witness[0].input_type (32 bytes)
```

## Example: Full Mint Flow

```rust
// 1. Setup
let issuer_key = SigningKey::generate(&mut OsRng);
let issuer_pubkey = issuer_key.verifying_key().to_bytes();
let token_id = [1u8; 32];

// 2. Create token (genesis)
let genesis_data = create_ct_info_data(0, &issuer_pubkey, 1_000_000, 0x01);
// ... build and submit genesis tx

// 3. Mint 100 tokens
let old_supply = 0u128;
let new_supply = 100u128;

// Input: ct-info cell with old supply
// Output: ct-info cell with new supply + ct-token cells

// Sign
let tx_hash = tx.hash().raw_data();
let mut message = Vec::new();
message.extend_from_slice(&tx_hash);
message.extend_from_slice(&old_supply.to_le_bytes());
message.extend_from_slice(&new_supply.to_le_bytes());
let signature = issuer_key.sign(&message);

// Compute mint commitment
let pc_gens = PedersenGens::default();
let mint_commitment = pc_gens.commit(Scalar::from(100u64), Scalar::zero());

// Create ct-token outputs with range proofs
// ... (see ct-token-type tests)

// Witness
let witness = WitnessArgs::new_builder()
    .input_type(Some(signature.to_bytes().into()))
    .output_type(Some(mint_commitment.compress().to_bytes().into()))
    .build();

// Submit transaction
```

## Testing

```bash
# Build
make build CONTRACT=ct-info-type

# Test
cargo test test_ct_info_genesis
cargo test test_ct_info_mint_basic
cargo test test_ct_info_mint_exceed_cap
cargo test test_ct_info_mint_without_signature
```

## Key Insights

1. **Supply is Public**: Minted amounts are visible on-chain (supply delta)
2. **Transfers are Private**: ct-token amounts remain confidential
3. **Single Info Cell**: One ct-info-type cell per token enforces serialization
4. **Mint Commitment**: Uses zero blinding factor (minted amount is public anyway)
5. **Signature Covers TX**: tx_hash in message prevents replay attacks
6. **Immutable Authority**: Issuer cannot be changed after genesis
7. **Cap Optional**: supply_cap = 0 means unlimited minting

## Security Notes

- ⚠️ Keep issuer private key secure (no key rotation after genesis)
- ⚠️ Set supply_cap in genesis (cannot change later)
- ⚠️ Minted amounts are PUBLIC (supply delta visible)
- ✓ Transfer amounts remain PRIVATE (Pedersen commitments)
- ✓ Recipients hidden by stealth addresses
- ✓ Range proofs prevent negative amounts
