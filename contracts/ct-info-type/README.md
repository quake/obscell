# ct-info-type

**CT Info Type** is a CKB type script that manages the global issuance information for a **Confidential Transaction (CT) Token**.
It handles the total supply, minting authorization, and tracks the total minted commitments, ensuring correct issuance of privacy-preserving tokens.

## Features
- **Global issuance management** for a CT Token
- **Tracks total minted commitment** without exposing individual amounts
- **Validates mint operations** including genesis issuance
- **Ensures max supply limits** are not exceeded

## How It Works
1. The initial CT Token genesis cell is created with a unique **TypeId** as its script argument.
2. All issuance-related information (e.g., `max_supply`, total minted commitment, minting rights) is stored in the **cell's output data**.
3. Authorized users can mint new tokens by consuming the Info Cell, providing proofs, and updating the output data to reflect the new total commitment.
4. Only mint or other total-supply-affecting operations reference this type script; ordinary transfers do not require it.

## Reference
- [Pedersen Commitments](https://en.wikipedia.org/wiki/Pedersen_commitment)
- [Bulletproofs](https://crypto.stanford.edu/bulletproofs/)
- [CKB TypeId](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#type-id)

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
