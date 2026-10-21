# record/

Written by `sh/address.sh`, one record per key, named after its role; commit both files of each record.

- `ROLE.pem`: the public key of key version 1, as gcloud returned it.
- `ROLE.json`: key, version, algorithm, protection level and address.

In `keeper.json`, `address` is the `KEEPER` of hydrex-conduit-executor, and `version` is hydrex-keeper's
`KMS_KEY_VERSION`. In `proposer.json`, `address` is hydrex-keeper's `PROPOSER`, and `version` is its
`PROPOSER_KMS_KEY_VERSION`. `sh/check.sh` fails if a `.pem` or the live key no longer derives to its `address`. To
derive it by hand:

```sh
openssl pkey -pubin -in record/keeper.pem -outform DER | tail -c 64 | openssl dgst -KECCAK-256 | tail -c 41
```
