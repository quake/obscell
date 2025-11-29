# Stealth Lock

**Stealth Lock** is a CKB lock script that enables privacy-preserving payments using **Stealth Address** style key derivation.
It allows a sender to generate a unique one-time payment address for each transfer without interacting with the receiver and without exposing the receiver’s real public key on-chain.

## Features
- **Stealth address support** using receiver’s `P` and `Q'` keys
- **One-time derived public key** per payment
- **Uses official CKB secp256k1 verification** via the upstream `ckb-auth` binary

## How It Works
1. The receiver publishes their stealth public keys `(P, Q')`.
2. The sender generates an ephemeral key and derives a unique payment public key.
3. The payment is locked to this derived key using the Stealth Lock script.
4. The receiver uses the matching private key to unlock the payment.

## Script Arguments
The lock script expects the following arguments:

- `P` — receiver’s main stealth public key (33 bytes)
- `Q'` — receiver’s view key hash (20 bytes)

## Reference
- [Bitcoin Stealth Address Proposal](https://github.com/genjix/bips/blob/master/bip-stealth.mediawiki)
- [CKB Discussion](https://github.com/Magickbase/neuron-public-issues/issues/100)


*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
