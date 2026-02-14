# ct-token-type

**CT Token Type** is a CKB type script that validates individual **Confidential Transaction (CT) Token** cells for private transfers.
It enforces commitment equality and range proof verification, enabling fully confidential token transfers between stealth addresses.

## Features
- **Validates commitment inputs and outputs** for each token transfer
- **Supports confidential amounts** using range proofs (e.g., Bulletproofs)
- **Works with Stealth Address Lock** to hide recipient addresses
- **Does not require the CT Info Type** for ordinary transfers

## How It Works
1. Each token transfer references input token cells locked by Stealth Lock.
2. The type script checks that the sum of input commitments equals the sum of output commitments.
3. All output cells must include valid range proofs to ensure amounts are non-negative without revealing them.
4. Transfers are confidential; neither amounts nor links between outputs are visible on-chain.

## Data and Witness Structure

CT token cells support two `output.data` formats:

### Format v1 (64 bytes) - Mint cells

Used for mint operations where blinding factor is zero (enforced by ct-info-type).

| Field | Size | Description |
|-------|------|-------------|
| commitment | 32 bytes | Compressed Ristretto point `C = v·G` (blinding = 0) |
| encrypted_amount | 32 bytes | XOR-encrypted amount with verification material |

### Format v2 (72 bytes) - Transfer cells

Used for transfer operations where blinding factors are non-zero.

| Field | Size | Description |
|-------|------|-------------|
| commitment | 32 bytes | Compressed Ristretto point `C = v·H + r·G` |
| encrypted_payload | 40 bytes | XOR-encrypted `amount (8B) \|\| blinding (32B)` |

The contract accepts any cell data >= 64 bytes and only reads the first 32 bytes (commitment) for verification.

### Encryption Details

```
key = SHA512("ct-amount-blinding-encryption" || shared_secret)[0..40]
encrypted_payload = (amount_le_bytes || blinding_bytes) XOR key
```

Receiver (Wallet) to recover balance metadata:

1. Compute DH shared secret from the lock script args (ephemeral pubkey in stealth-lock)
2. Decrypt using the same key derivation
3. Verify: `commitment == commit(amount, blinding)` to confirm correctness

On-Chain Verification (CT Token Type Script):

1. Sum check is trivial, because commitments are homomorphic, just validates Σ inputs.commitment == Σ outputs.commitment
2. Actual bulletproof goes into the witness (in WitnessArgs.output_type field), we only need to check the range proof validity for outputs since inputs are already checked by the ct-token-type script.

## Reference
- [Pedersen Commitments](https://en.wikipedia.org/wiki/Pedersen_commitment)
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/)


*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
