# hydrex-keeper-key

The Cloud KMS key that signs the weekly Hydrex vote of the Klima "Carbon Impact" conduit. Its Ethereum address is the
`KEEPER` of the Safe module in [hydrex-conduit-executor](https://github.com/ldeso/hydrex-conduit-executor), and
[hydrex-keeper](https://github.com/ldeso/hydrex-keeper) signs with it from a Cloud Run job. The private key never leaves
the HSM. This repository holds only public material: the scripts in `sh/`, the IAM policy and audit config in `policy/`
that they write in full, and the public key and address in `record/`.

`KEY_PROJECT` holds one key ring and one key, administered by `ADMIN_MEMBER`, a person or a small group.
`KEEPER_PROJECT` holds the keeper, whose service account `KEEPER_SA` is the key's only signer.

## Setup

Needs `gcloud`, `jq` and OpenSSL 3.2 or newer. `sh/setup.sh` needs `roles/owner` on the key project. The other scripts
run as `ADMIN_MEMBER`; `sh/grant.sh` and `sh/check.sh` also need `roles/iam.serviceAccountViewer` on `KEEPER_SA`, and
`sh/check.sh` `roles/monitoring.viewer` on the key project. Every script is safe to re-run.

1. **Configure.** `cp config.env.example config.env`, then fill in `KEY_PROJECT`, `KEEPER_PROJECT`, `ADMIN_MEMBER` and
   `ALERT_EMAIL`.
2. **Create the key.** `sh/setup.sh` enables the APIs, creates the key ring and the key (asymmetric signing, secp256k1,
   HSM, 120-day destroy window), writes the key's IAM policy, turns on the KMS audit logs, and emails `ALERT_EMAIL` on
   any change under the key ring. A key of another kind under the same name is refused.
3. **Record the address.** `sh/address.sh` writes `record/`; commit it. A record for another key or address is kept
   unless `--force`. `address` is the module's `KEEPER` and cannot change there, so a new key means a new module.
4. **Grant the keeper.** Once hydrex-keeper's `sh/setup.sh` has printed the keeper's service account, set `KEEPER_SA`
   and run `sh/grant.sh`.
5. **Check for drift.** `sh/check.sh` compares the key, its IAM policy, the audit config, the alert and `KEEPER_SA` with
   `config.env`, `policy/` and `record/`, read-only: one version, enabled, deriving to the recorded address; the alert
   enabled and notifying `ALERT_EMAIL`; no user-managed key of `KEEPER_SA`; nobody able to act as it.

The `check` workflow runs `sh/check.sh` every Friday and on demand, as a read-only service account in the key project
(`roles/cloudkms.viewer` on the key ring, `roles/iam.securityReviewer` and `roles/monitoring.viewer` on the project,
`roles/iam.serviceAccountViewer` on `KEEPER_SA`) reached by Workload Identity Federation through the `WIF_PROVIDER` and
`CI_SERVICE_ACCOUNT` repository variables. It builds `config.env` from the repository variables named in
`config.env.example`.

Outside the scripts: hardware 2FA on `ADMIN_MEMBER`; no owner of the key project beyond `ADMIN_MEMBER`, since an owner
can re-grant `cloudkms.admin`; the KMS audit logs sunk to a bucket the admins do not own, since `_Default` keeps them
for 30 days and an admin has 120 days to cancel a scheduled destruction; and
`iam.managed.disableServiceAccountKeyCreation` on the keeper project, since `check.sh` only detects keys.

## Development

`npm ci` once, then `npm run format` before committing. `test/sh/golden.sh` runs the scripts under `dash` (or
`$TEST_SH`) against a fake `gcloud` and compares the calls and output with `test/sh/golden/`; `--update` rewrites them.
CI runs it with Prettier, `shellcheck` and `reuse lint` on every push, and Dependabot updates the pinned Actions and npm
packages.

## License

MIT, REUSE compliant.
