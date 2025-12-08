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

Each CT token cell stores exactly 64 bytes in `output.data`:

1. commitment: a 32 bytes compressed ristretto commitment that hides the token amount `C = v·H + r·G`, where `v` - amount, `r` - blinding, `H, G` - fixed generators

2. encrypted_amount_and_blinding: a 32-byte encrypted payload containing v (8 bytes) || r (24 bytes) enabling receiver recovery, encrypted using a symmetric key derived from cell’s stealth lock script args.

Receiver (Wallet) to recover balance metadata:

1. Compute DH shared secret from the lock script args. (DONE in stealth script wallet demo)
2. Decrypt: key = H(shared), plaintext = encrypted_amount_and_blinding XOR key, v = plaintext[0..8), r = plaintext[8..32)

On-Chain Verification (CT Token Type Script):

1. Sum check is trivial, because commitments are homomorphic, just validates Σ inputs.commitment == Σ outputs.commitment
2. Actual bulletproof goes into the witness (in WitnessArgs.output_type field), we only need to check the range proof validity for outputs since inputs are already checked by the ct-token-type script.

## Reference
- [Pedersen Commitments](https://en.wikipedia.org/wiki/Pedersen_commitment)
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/)


*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
