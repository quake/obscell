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

## Reference
- [Pedersen Commitments](https://en.wikipedia.org/wiki/Pedersen_commitment)
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/)


*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
