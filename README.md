# hydrex-keeper-key

The Cloud KMS keys that sign the Hydrex votes of [hydrex-keeper](https://github.com/ldeso/hydrex-keeper), from a Cloud
Run job, one key per role:

- **keeper**, `KEEPER_KEY`: signs the weekly vote of the Klima "Carbon Impact" conduit. Its Ethereum address is the
  `KEEPER` of the Safe module in [hydrex-conduit-executor](https://github.com/ldeso/hydrex-conduit-executor).
- **proposer**, `PROPOSER_KEY`: signs the votes of `ImmutableVeTokenConduit`, version 2 of hydrex-conduit, at
  `0x692c323B425A9DfeebE302F56168a7798D93EAC5` on Base. Anyone may propose them, so the key has no on-chain privileges
  and only holds gas ETH. It has an address of its own because the two conduits vote in the same blocks: from one
  address, each vote's nonce would depend on the other's.

The private keys never leave the HSM. This repository holds only public material: the scripts in `sh/`, the IAM policy
and audit config in `policy/` that they write in full, and the public keys and addresses in `record/`.

`KEY_PROJECT` holds one key ring and its keys, administered by `ADMIN_MEMBER`, a person or a small group.
`KEEPER_PROJECT` holds the keeper, whose service account `KEEPER_SA` is the only signer of each key.

## Setup

Needs `gcloud`, `jq` and OpenSSL 3.2 or newer. `sh/setup.sh` needs `roles/owner` on the key project. The other scripts
run as `ADMIN_MEMBER`; `sh/grant.sh` and `sh/check.sh` also need `roles/iam.serviceAccountViewer` on `KEEPER_SA`, and
`sh/check.sh` `roles/monitoring.viewer` on the key project. Every script is safe to re-run.

1. **Configure.** `cp config.env.example config.env`, then fill in `KEY_PROJECT`, `KEEPER_PROJECT`, `ADMIN_MEMBER`,
   `ALERT_EMAIL` and `PROPOSER_KEY`, for example `hydrex-proposer-v1`. `KEEPER_KEY` defaults to `hydrex-keeper-v1`; an
   empty `PROPOSER_KEY` means no proposer key. A leftover `KEY` is an error: rename it to `KEEPER_KEY`.
2. **Create the keys.** `sh/setup.sh` enables the APIs, creates the key ring and each key (asymmetric signing,
   secp256k1, HSM, 120-day destroy window), writes each key's IAM policy, turns on the KMS audit logs, and emails
   `ALERT_EMAIL` on any change under the key ring. A key of another kind under the same name is refused.
3. **Record the addresses.** `sh/address.sh [ROLE...]` writes `record/ROLE.json` and `record/ROLE.pem` for each role, by
   default every role with a key, and prints `ROLE ADDRESS`; commit them. A record for another key or address is kept
   unless `--force`, which applies only to the roles handled. The keeper's `address` is the module's `KEEPER` and cannot
   change there, so a new keeper key means a new module. A new proposer key means a new `PROPOSER` in hydrex-keeper's
   config, and funding that address.
4. **Grant the keeper.** Once hydrex-keeper's `sh/setup.sh` has printed the keeper's service account, set `KEEPER_SA`
   and run `sh/grant.sh`, which writes the IAM policy of each key.
5. **Check for drift.** `sh/check.sh` compares each key, its IAM policy, the audit config, the alert and `KEEPER_SA`
   with `config.env`, `policy/` and `record/`, read-only: one version per key, enabled, deriving to the recorded
   address; the alert enabled and notifying `ALERT_EMAIL`; no user-managed key of `KEEPER_SA`; nobody able to act as it.

To add the proposer key to an existing setup, set `PROPOSER_KEY` and run `sh/setup.sh`, which leaves the keeper key as
it is. Once the proposer's version 1 is enabled, `sh/address.sh proposer` writes its record alone.

The `check` workflow runs `sh/check.sh` every Friday and on demand, as a read-only service account in the key project
(`roles/cloudkms.viewer` on the key ring, `roles/iam.securityReviewer` and `roles/monitoring.viewer` on the project,
`roles/iam.serviceAccountViewer` on `KEEPER_SA`) reached by Workload Identity Federation through the `WIF_PROVIDER` and
`CI_SERVICE_ACCOUNT` repository variables. It builds `config.env` from the repository variables named in
`config.env.example`: set `PROPOSER_KEY` once `record/proposer.json` is committed, since `sh/check.sh` fails on either
without the other, and rename a `KEY` variable, if one is set, to `KEEPER_KEY`.

Outside the scripts: hardware 2FA on `ADMIN_MEMBER`; no owner of the key project beyond `ADMIN_MEMBER`, since an owner
can re-grant `cloudkms.admin`; the KMS audit logs sunk to a bucket the admins do not own, since `_Default` keeps them
for 30 days and an admin has 120 days to cancel a scheduled destruction; and
`iam.managed.disableServiceAccountKeyCreation` on the keeper project, since `check.sh` only detects keys.

## Development

`shfmt -w .` formats the shell scripts before committing, with the settings in `.editorconfig`; Markdown is wrapped at
120 columns. `test/sh/golden.sh` runs the scripts under `dash` (or `$TEST_SH`) against a fake `gcloud` and compares the
calls and output with `test/sh/golden/`; `--update` rewrites them. CI runs it with `shfmt`, `shellcheck` and
`reuse lint` on every push. Dependabot updates the pinned Actions; `ci.yml` pins the `fsfe/reuse` and `mvdan/shfmt`
images by digest, updated by hand.

## License

MIT, REUSE compliant.
