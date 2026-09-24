# hydrex-keeper-key

The Hydrex keeper is a service that casts one on-chain vote a week through `hydrex-conduit-executor`, a Safe module that accepts transactions from a single fixed Ethereum address, its `KEEPER`. This repo creates the key behind that address in Google Cloud KMS, records the address so the module can be deployed with it, grants the keeper service the right to sign with the key, and checks that nothing has drifted since. The private key never leaves the HSM; this repo holds only public material.

Two GCP projects. The key project holds one key ring and one key, administered by one person or a small group, `ADMIN_MEMBER`. The keeper project holds the keeper service, a Cloud Run job, and receives one grant: signer on the key. IAM on the key is always written in full from `policy/key.iam.json.tmpl`; nothing is ever added to what is there.

## Prerequisites

`gcloud`, `jq`, and `openssl` 3.2 or newer.

| Script | Needs |
|---|---|
| `setup.sh` | `roles/owner` on the key project |
| `address.sh` | being `ADMIN_MEMBER`, or a member of it if it is a group |
| `grant.sh`, `check.sh` | as above, plus `roles/iam.serviceAccountViewer` on the keeper project |

## 1. Configure

```sh
cp config.env.example config.env
```

Fill in every value. `ADMIN_MEMBER` is `user:EMAIL` for one admin or `group:EMAIL` for a Google group. Leave `KEEPER_SA`, the keeper service's service account (SA) email, empty until that account exists in the keeper project.

Location defaults to `us`. One signature a week makes latency irrelevant; multi-region gives availability. Changing it later changes the resource names and the record, so choose once.

## 2. Create the key project resources

```sh
sh/setup.sh
```

Enables the KMS API, creates the key ring and the key (asymmetric signing, secp256k1, HSM, 120-day destroy window), writes the key IAM policy, and turns on KMS Data Access audit logs. Safe to re-run; a second run changes nothing. An existing key with different attributes is refused.

Confirm in the console: one ring, one key, one version, HSM, secp256k1, 120 days, only `ADMIN_MEMBER` on the key, all three KMS audit log types on.

## 3. Record the address

```sh
sh/address.sh
git add record/ && git commit -m "record: keeper key version 1"
```

Writes `record/keeper.pem` and `record/keeper.json`. Re-running against the same key changes nothing. If the record names a different key or address it refuses; `--force` overrides, which is only right when a new key and a new module are intended.

To verify the address without the script:

```sh
openssl pkey -pubin -in record/keeper.pem -outform DER -out keeper.der
tail -c 64 keeper.der | openssl dgst -KECCAK-256 | tail -c 41
```

## 4. Deploy the module

`address` in `record/keeper.json` is the `KEEPER` of `hydrex-conduit-executor`. It is immutable in the module, so a new key means a new module. Have the module's deploy script read the address from a copy of `record/keeper.json` rather than paste it.

## 5. Grant the keeper

Once the keeper service's service account exists, set `KEEPER_SA` in `config.env` and run:

```sh
sh/grant.sh
```

Safe to re-run.

## 6. Check for drift

```sh
sh/check.sh
```

Read-only. Fails if the live key no longer derives to the recorded address, a second version exists, version 1 is not enabled, key attributes or destroy window changed, the key IAM policy differs from the template, the audit config is off, or `KEEPER_SA` has a user-managed key. Run it after each step above. After step 5, `KEEPER_SA` must be set in `config.env` or the grant reads as drift.

CI runs it every Friday after the vote, and on demand from the Actions tab. One-time setup, done once by an admin:

1. In the key project, create a service account for CI, say `ci-check@KEY_PROJECT.iam.gserviceaccount.com`. Grant it `roles/cloudkms.viewer` on the key ring and `roles/iam.securityReviewer` on the project, and, once `KEEPER_SA` exists, `roles/iam.serviceAccountViewer` on `KEEPER_SA`. It can read everything `check.sh` needs and write nothing.
2. Create a Workload Identity Federation pool and an OIDC provider for GitHub (`--issuer-uri=https://token.actions.githubusercontent.com`, attribute mapping `google.subject=assertion.sub,attribute.repository=assertion.repository`, attribute condition restricting `assertion.repository` to this repo). Grant the pool's principal set for this repo `roles/iam.workloadIdentityUser` on the CI service account.
3. Set repository variables (Settings, Secrets and variables, Actions, Variables): `KEY_PROJECT`, `KEEPER_PROJECT`, `LOCATION`, `KEY_RING` and `KEY` (only if changed from the defaults), `ADMIN_MEMBER`, `KEEPER_SA` (empty until step 5), `WIF_PROVIDER` (the provider's full resource name) and `CI_SERVICE_ACCOUNT`. These are public material, not secrets.
4. Run the workflow once by hand and confirm the `check` job is green.

## Outside the scripts

1. Enforce hardware 2FA on the admin account, or on every member of the admin group.
2. KMS audit logs land in `_Default`, which keeps 30 days. Sink them to a locked bucket with longer retention in a project the admins do not own.
3. Admins can schedule the key's destruction and cancel it within 120 days. Alert on `DestroyCryptoKeyVersion` and `UpdateCryptoKeyVersion`.
4. A project owner can always re-grant `cloudkms.admin`. The key project's owners must be `ADMIN_MEMBER` or fewer, with no org-level owner reaching it. Nothing here can check this.
5. `KEEPER_SA` can sign, so a downloadable key for it could sign from anywhere. Enforce `iam.managed.disableServiceAccountKeyCreation` on the keeper project. `check.sh` only detects a user-managed key on `KEEPER_SA`.

## Development

`test/run.sh` runs every script under `dash` against a fake `gcloud` and diffs the calls against `test/golden/`; `--update` regenerates after an intended change. CI runs `shellcheck -s sh`, `sh -n`, `reuse lint` and these tests on every push; the `dash` run catches bashisms. CI reads, never writes: the scheduled `check` job is the only one with GCP access, through a viewer-only service account. Actions are pinned by commit and updated by Dependabot.
