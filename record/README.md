# record/

Written by `sh/address.sh`. Commit both files.

- `keeper.pem`: SPKI public key of key version 1, as gcloud returned it.
- `keeper.json`: key, version, algorithm, protection level, address.

`sh/check.sh` fails if `keeper.pem` or the live key no longer derives to `address`. `hydrex-conduit-executor` is deployed with `address` as its `KEEPER`.
