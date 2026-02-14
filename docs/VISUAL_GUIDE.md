# CT-Info-Type Visual Guide

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Obscell Token System                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ stealth-lock │  │ ct-token-type│  │ ct-info-type │      │
│  │   (DONE)     │  │   (DONE)     │  │    (NEW)     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│        │                  │                  │               │
│        │                  │                  │               │
│   Hide Recipients    Hide Amounts      Track Supply         │
│   (Stealth Addr)    (Commitments)   (Public Minting)        │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Cell Structure

```
CT-Info-Type Cell (57 bytes)
┌────────────────────────────────────────────────┐
│ Type Script                                    │
│ ┌──────────────────────────────────────────┐  │
│ │ Code: ct-info-type script                │  │
│ │ Args: [token_id: 32B][version: 1B]       │  │
│ └──────────────────────────────────────────┘  │
│                                                │
│ Data (57 bytes)                                │
│ ┌──────────────────────────────────────────┐  │
│ │ total_supply:    u128    [0..16]         │  │
│ │ supply_cap:      u128    [16..32]        │  │
│ │ reserved:        [u8;24] [32..56]        │  │
│ │ flags:           u8      [56]            │  │
│ └──────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘

CT-Token-Type Cell (72 bytes)
┌────────────────────────────────────────────────┐
│ Type Script                                    │
│ ┌──────────────────────────────────────────┐  │
│ │ Code: ct-token-type script               │  │
│ │ Args: [token_id: 32B]                    │  │
│ └──────────────────────────────────────────┘  │
│                                                │
│ Data (72 bytes)                                │
│ ┌──────────────────────────────────────────┐  │
│ │ commitment:  [u8;32] [0..32]             │  │
│ │ encrypted:   [u8;40] [32..72]            │  │
│ │   (amount 8B + blinding 32B)             │  │
│ └──────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
```

## Transaction Flow

### Genesis Transaction (Create Token)

```
┌─────────────────────────────────────────────────────────┐
│ Genesis TX: Create New Token                            │
└─────────────────────────────────────────────────────────┘

Inputs: (none)

Outputs:
┌─────────────────────────────────────────┐
│ CT-Info Cell                            │
│ ┌─────────────────────────────────────┐ │
│ │ supply:  0                          │ │
│ │ cap:     1,000,000                  │ │
│ │ flags:   MINTABLE                   │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘

Witnesses: (none required)

Validation:
✓ flags & MINTABLE == 1
```

### Mint Transaction (Simple)

```
┌─────────────────────────────────────────────────────────┐
│ Mint TX: Mint 100 Tokens                                │
└─────────────────────────────────────────────────────────┘

Inputs:
┌─────────────────────────────────────────┐
│ CT-Info Cell                            │
│   supply:  0                            │
└─────────────────────────────────────────┘

Outputs:
┌─────────────────────────────────────────┐
│ CT-Info Cell                            │
│   supply:  100  ← increased             │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CT-Token Cell #1                        │
│   commitment:  C1 (~60 tokens)          │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CT-Token Cell #2                        │
│   commitment:  C2 (~40 tokens)          │
└─────────────────────────────────────────┘

Witnesses:
[0] ┌────────────────────────────────────┐
    │ output_type: mint_commitment(100)  │ ← for ct-token
    └────────────────────────────────────┘
[1] ┌────────────────────────────────────┐
    │ output_type: range_proof           │ ← Bulletproofs
    └────────────────────────────────────┘

Validation:
ct-info-type:
  ✓ supply increase: 100 - 0 = 100 > 0
  ✓ supply <= cap: 100 <= 1,000,000
  ✓ immutable fields unchanged

ct-token-type:
  ✓ 0 + mint_commitment(100) = C1 + C2
  ✓ range proofs valid
```

### Mint + Transfer Transaction (Complex)

```
┌─────────────────────────────────────────────────────────┐
│ Mint+Transfer TX: Mint 100 + Combine with 50 Existing   │
└─────────────────────────────────────────────────────────┘

Inputs:
┌─────────────────────────────────────────┐
│ CT-Info Cell                            │
│   supply:  1000                         │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CT-Token Cell (existing)                │
│   commitment:  C_in (~50 tokens)        │
└─────────────────────────────────────────┘

Outputs:
┌─────────────────────────────────────────┐
│ CT-Info Cell                            │
│   supply:  1100  ← +100                 │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CT-Token Cell #1                        │
│   commitment:  C1 (~90 tokens)          │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│ CT-Token Cell #2                        │
│   commitment:  C2 (~60 tokens)          │
└─────────────────────────────────────────┘

Balance:
  Inputs:  50 (existing tokens)
  Minted:  100 (new tokens)
  Total:   150
  Outputs: 90 + 60 = 150 ✓

Validation:
ct-token-type:
  ✓ C_in + mint_commitment(100) = C1 + C2
  ✓ This proves: 50 + 100 = 150 (split as 90 + 60)
```

## Authorization Model

```
┌─────────────────────────────────────────────────────────┐
│ Lock Script Authorization                               │
└─────────────────────────────────────────────────────────┘

CKB's Native Security Model:
┌────────────────────────────────────────┐
│ Lock Script = WHO can spend the cell   │
│ Type Script = WHAT transitions valid   │
│                                        │
│ ct-info-type uses this separation:     │
│ - Lock script controls mint permission │
│ - Type script validates state changes  │
└────────────────────────────────────────┘

Mint Authorization Flow:
┌────────────────────────────────────────┐
│ 1. ct-info cell has a lock script     │
│    (e.g., secp256k1, multisig, DAO)   │
│                                        │
│ 2. To mint, must unlock the cell      │
│    (satisfy lock script requirements)  │
│                                        │
│ 3. ct-info-type validates:            │
│    - Supply increase is valid          │
│    - Cap not exceeded                  │
│    - Immutable fields unchanged        │
│                                        │
│ Benefits:                              │
│ - Flexible authorization schemes       │
│ - Reuse existing lock scripts          │
│ - Multi-sig, time-locks, DAOs, etc.   │
└────────────────────────────────────────┘
```

## Mint Commitment Flow

```
┌─────────────────────────────────────────────────────────┐
│ Mint Commitment Computation & Verification              │
└─────────────────────────────────────────────────────────┘

Off-chain (Transaction Construction):
┌────────────────────────────────────────┐
│ 1. Calculate minted amount:            │
│    minted = new_supply - old_supply    │
│                                        │
│ 2. Create commitment:                  │
│    mint_commitment = minted * G + 0*H  │
│    (zero blinding factor)              │
│                                        │
│ 3. Compress and attach:                │
│    witness[0].output_type =            │
│      mint_commitment.compress()        │
└────────────────────────────────────────┘

On-chain (ct-token-type validation):
┌────────────────────────────────────────┐
│ 1. Load mint_commitment from witness   │
│                                        │
│ 2. Sum input commitments:              │
│    input_sum = Σ(input_commitments)    │
│                                        │
│ 3. Sum output commitments:             │
│    output_sum = Σ(output_commitments)  │
│                                        │
│ 4. Verify balance:                     │
│    input_sum + mint_commitment         │
│      == output_sum                     │
│                                        │
│ 5. Verify range proofs for outputs    │
└────────────────────────────────────────┘
```

## State Transitions

```
Token Lifecycle:

  Genesis            Mint #1           Mint #2          Transfer
     │                 │                 │                 │
     ▼                 ▼                 ▼                 ▼
┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐
│ supply: │      │ supply: │      │ supply: │      │ supply: │
│    0    │─────▶│   100   │─────▶│   300   │─────▶│   300   │
│         │      │         │      │         │      │         │
│  (no    │      │ (+100)  │      │ (+200)  │      │ (same)  │
│ tokens) │      │         │      │         │      │         │
└─────────┘      └─────────┘      └─────────┘      └─────────┘
                       │                │                │
                       ▼                ▼                ▼
                 ┌──────────┐    ┌──────────┐    ┌──────────┐
                 │ 2 CT-Token│   │ 4 CT-Token│   │ 3 CT-Token│
                 │   cells   │   │   cells   │   │   cells   │
                 │ (sum=100) │   │ (sum=300) │   │ (sum=300) │
                 └──────────┘    └──────────┘    └──────────┘

Note: During transfers, supply stays constant but CT-Token cells
      are consumed and recreated with new commitments/owners
```

## Error Handling

```
Validation Decision Tree:

Input Count?
  ├─ 0: Genesis
  │   ├─ flags & MINTABLE == 0? → MintingDisabled (9)
  │   └─ All good → PASS ✓
  │
  └─ 1: Mint
      ├─ Output Count != 1? → InvalidCellCount (7)
      ├─ Immutable fields changed? → ImmutableFieldChanged (8)
      ├─ flags & MINTABLE == 0? → MintingDisabled (9)
      ├─ minted <= 0? → InvalidMintAmount (11)
      ├─ new_supply > cap? → SupplyCapExceeded (10)
      ├─ Overflow? → SupplyOverflow (12)
      └─ All good → PASS ✓
      (Lock script handles authorization separately)

Other:
  └─ Input Count > 1 or != Output Count → InvalidCellCount (7)
```

## Privacy Model

```
┌────────────────────────────────────────────────────────┐
│                What's PUBLIC vs PRIVATE                 │
├────────────────────────────────────────────────────────┤
│                                                         │
│  PUBLIC (Visible on-chain):                            │
│  ✓ Total token supply                                  │
│  ✓ Supply increases (minted amounts)                   │
│  ✓ Supply cap                                          │
│  ✓ Token exists                                        │
│                                                         │
│  PRIVATE (Hidden by crypto):                           │
│  ✓ Individual transfer amounts (Pedersen commitments)  │
│  ✓ Individual balances (encrypted in cells)            │
│  ✓ Recipients (stealth addresses)                      │
│  ✓ Exact amounts in commitments (range proofs)         │
│                                                         │
└────────────────────────────────────────────────────────┘

Tradeoff: Mint amounts are public to enable supply auditing,
          but transfer amounts remain private.
```

## Comparison: Before vs After

```
BEFORE (No Minting):
┌────────────────────────────────────┐
│ stealth-lock:    Hides recipients  │
│ ct-token-type:   Hides amounts     │
│ ct-info-type:    (not implemented) │
│                                    │
│ Problem: How to create new tokens? │
└────────────────────────────────────┘

AFTER (With Minting):
┌────────────────────────────────────┐
│ stealth-lock:    Hides recipients  │
│ ct-token-type:   Hides amounts     │
│                  + mint support    │
│ ct-info-type:    Tracks supply     │
│                  + authorizes mint │
│                                    │
│ Solution: Controlled minting! ✓    │
└────────────────────────────────────┘
```

## Summary

This visual guide shows how ct-info-type enables:

1. **Genesis**: Create tokens with lock script authority
2. **Minting**: Increase supply with lock script authorization
3. **Tracking**: Public supply for auditing
4. **Integration**: Works with existing stealth + ct-token
5. **Security**: Lock script authorization + cap enforcement
6. **Privacy**: Transfers remain confidential
