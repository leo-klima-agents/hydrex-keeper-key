# hydrex-keeper-key

Part two of three. Part one, `hydrex-conduit-executor`, is an immutable Safe module whose `KEEPER` is an EOA address. Part three signs with that key from a Cloud Run job. This repo creates the key in Cloud KMS, records its Ethereum address for part one, and checks for drift. No secrets: the private key never leaves the HSM.

## Model

Two GCP projects.

- **Key project**: one key ring, one key, nothing else. `roles/cloudkms.admin` on the key for a small human group behind hardware 2FA. KMS Data Access audit logs on. Destroy window 120 days.
- **Keeper project**: the runtime. Receives one cross-project grant: `roles/cloudkms.signer` and `roles/cloudkms.publicKeyViewer` on the key, to the job's service account.

IAM is written authoritatively: one template, `policy/key.iam.json.tmpl`, written in full by `setup.sh` and `grant.sh`. Nothing adds a binding to what is there.

POSIX shell over `gcloud`, not OpenTofu: five resources, no state, no providers, every call readable.

## Layout

```
config.env.example           inputs; copy to config.env (gitignored)
sh/lib.sh                    config, checks, policy render, authoritative IAM
sh/setup.sh                  key project resources, idempotent
sh/grant.sh                  the cross-project binding, idempotent
sh/address.sh                public key -> address, writes record/
sh/check.sh                  live state vs record/ and expected IAM
policy/key.iam.json.tmpl     complete key IAM policy
policy/audit.json            KMS auditConfigs entry
record/                      keeper.pem, keeper.json (written by address.sh)
test/fake-gcloud, test/run.sh, test/golden/
.github/workflows/ci.yml     lint and golden tests on push
```

## 1. Prerequisites

`gcloud` >= 470.0.0 and `jq`. `openssl` and `cast` ([Foundry](https://getfoundry.sh)) for `address.sh` and `check.sh`. Any POSIX `sh` with `awk`, `od`, `tail` and `tr`; CI uses `dash`.

| Script | Where | Role |
|---|---|---|
| `setup.sh` | key project | `roles/owner`, or `serviceusage.serviceUsageAdmin` + `cloudkms.admin` + `resourcemanager.projectIamAdmin` |
| `setup.sh` step 6 | org or folder | `roles/orgpolicy.policyAdmin`; optional, warns without it |
| `address.sh` | key | `roles/cloudkms.admin` via the admin group |
| `grant.sh` | key, keeper project | admin group; `roles/iam.serviceAccountViewer` on the keeper project |
| `check.sh` | key project | the admin group, or `roles/viewer` plus `roles/cloudkms.publicKeyViewer` granted at project level (the key's own policy is the template and would drop it) |

## 2. config.env

```sh
cp config.env.example config.env
```

`KEEPER_SA` stays empty until part three exists.

**Location.** Default `us`. One signature per weekly vote, so latency is irrelevant; multi-region buys availability; `us` matches where Base's sequencer is observed to run. Changing it changes the resource names and the record, so choose once.

## 3. setup.sh

```sh
sh/setup.sh
```

1. Enables `cloudkms.googleapis.com`.
2. Creates the key ring if absent.
3. Creates the key if absent: `asymmetric-signing`, `ec-sign-secp256k1-sha256`, `hsm`, destroy window `120d`. An existing key with other attributes or another window is refused; the window is immutable, so use another `KEY` name.
4. Writes the key IAM policy from the template. Admin group alone until `KEEPER_SA` is set.
5. Replaces the `cloudkms.googleapis.com` audit entry in the project policy. Project bindings are left alone.
6. Enforces `iam.disableServiceAccountKeyCreation` if permitted; otherwise warns.
7. Prints the version 1 resource name and state. HSM generation takes a moment.

Confirm in the console: one ring, one key, one version, HSM, secp256k1, 120 days, admin group only, all three KMS audit log types on. A second run makes no writes.

## 4. address.sh

```sh
sh/address.sh
git add record/ && git commit -m "record: keeper key version 1"
```

Same key: no-op. Different key or address in the record: refused unless `--force`.

By hand:

```sh
gcloud kms keys versions get-public-key .../cryptoKeyVersions/1 --output-file=keeper.pem
openssl pkey -pubin -in keeper.pem -outform DER -out keeper.der   # 88 bytes
XY=$(tail -c 64 keeper.der | od -An -v -tx1 | tr -d ' \n')       # X||Y
HASH=$(cast keccak "0x$XY")
cast to-check-sum-address "0x$(printf '%s' "$HASH" | tail -c 40)"
```

`test/golden/address.txt` runs this over the secp256k1 generator point and gets `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`, the known address for private key 1.

## 5. Part one

`address` in `record/keeper.json` is `KEEPER`. `KEEPER` is immutable, so a new key means a new module; this repo never creates version 2. Part one's deploy script should read the address from a copy of `record/keeper.json` rather than repeat the literal.

## 6. grant.sh

Set `KEEPER_SA` in `config.env`, then:

```sh
sh/grant.sh
```

Verifies the account exists, writes the full policy. Idempotent.

## 7. check.sh

```sh
sh/check.sh
```

Read-only. Re-derives the address from the live key and compares it with `record/`; asserts version 1 is `ENABLED` and the only version, key and version attributes and destroy window are unchanged, the key IAM policy equals the template, the audit entry is present, and the org policy is enforced. Every check runs; exit 1 if any failed. Once `grant.sh` has run, `KEEPER_SA` must be set in `config.env` or the grant reads as drift.

Run it by hand after each step and periodically. Part three's scheduler can take it over.

## Manual steps

1. **Hardware 2FA** on the admin group, enforced in Workspace.
2. **Audit log retention.** `_Default` keeps 30 days. Sink KMS logs to a locked bucket with 400+ days, in a project the admins do not own.
3. **Scheduled destruction.** Admins can schedule and cancel it within 120 days. Alert on `DestroyCryptoKeyVersion` and `UpdateCryptoKeyVersion`.
4. **Project ownership is the root.** An owner can re-grant `cloudkms.admin`. Key project owners must be the admin group or fewer, with no org-level owner reaching it. `check.sh` cannot assert this.

## Tests

```sh
test/run.sh            # goldens under dash
test/run.sh --update   # regenerate after an intended change
```

CI: `shellcheck -s sh`, `checkbashisms`, `sh -n`, `reuse lint`, goldens. Goldens hold every gcloud call, the exact policy JSON written, exit codes and files written. Nothing in CI has GCP access.

## Open decisions

1. Admin group membership, and whether key project owners are the same people.
2. Who runs `check.sh` and how often, until part three schedules it.

## Constraints

- `gcloud kms asymmetric-sign` hashes its input, so signature-recovery tests belong in part three.
- The address is the property of key version 1 alone. `check.sh` fails if another appears.

## License

MIT. REUSE compliant.
