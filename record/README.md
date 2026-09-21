# record/

Written by `sh/address.sh` after the key exists. Commit both files.

- `keeper.pem`: the SPKI public key of key version 1, exactly as `gcloud kms keys versions get-public-key` returned it.
- `keeper.json`: key resource name, version, algorithm, protection level, the checksummed Ethereum address, and the SHA-256 of `keeper.pem`.

`sh/check.sh` re-derives the address from the live key and fails if it differs from `keeper.json`. Part one's `script/Deploy.s.sol` takes its `KEEPER` value from `address` in `keeper.json`.
