# record/

Written by `sh/address.sh`. Commit both files.

- `keeper.pem`: SPKI public key of key version 1, as gcloud returned it.
- `keeper.json`: key, version, algorithm, protection level, address, SHA-256 of the PEM.

`sh/check.sh` fails if the live key no longer derives to `address`. Part one takes `KEEPER` from `address`.
