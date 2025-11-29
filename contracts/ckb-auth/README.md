This project includes a prebuilt ckb-auth binary, which is required for signature verification inside the contract.
The binary is not built by this repository. It is compiled from the official nervos project:

1. Source repository: https://github.com/nervosnetwork/ckb-auth
2. Commit hash: f81d03b
3. Build method: make all-via-docker (see the upstream documentation for details)

Compare the output with the checksum provided in this repository. If they match, the binary is safe to use:

```bash
sha256sum repo-path-of-ckb-auth/build/auth
51d06e5c5b088424c51a6205eeede1a33054fd752a101cad0d545f32e01da33d
```
