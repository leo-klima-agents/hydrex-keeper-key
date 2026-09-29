# record/

Written by `sh/address.sh`; commit both files.

- `keeper.pem`: the public key of key version 1, as gcloud returned it.
- `keeper.json`: key, version, algorithm, protection level and address.

`address` is the `KEEPER` of hydrex-conduit-executor, and `version` is hydrex-keeper's `KMS_KEY_VERSION`. `sh/check.sh`
fails if `keeper.pem` or the live key no longer derives to `address`. To derive it by hand:

```sh
openssl pkey -pubin -in record/keeper.pem -outform DER | tail -c 64 | openssl dgst -KECCAK-256 | tail -c 41
```
