# hydrex-keeper-key

Part two of three. Part one, `hydrex-conduit-executor`, is an immutable Safe module whose `KEEPER` is an EOA address. Part three signs with that key from a Cloud Run job. This repo creates the key in Cloud KMS, records its Ethereum address for part one, and detects drift. No secrets: the private key never leaves the HSM.

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
.github/workflows/ci.yml     lint + goldens on push; check.sh weekly via WIF
```

## 1. Prerequisites

`gcloud` >= 470.0.0 and `jq`. `openssl` and `cast` ([Foundry](https://getfoundry.sh)) for `address.sh` and `check.sh`. Any POSIX `sh`; CI uses `dash`.

| Script | Where | Role |
|---|---|---|
| `setup.sh` | key project | `roles/owner`, or `serviceusage.serviceUsageAdmin` + `cloudkms.admin` + `resourcemanager.projectIamAdmin` |
| `setup.sh` step 6 | org or folder | `roles/orgpolicy.policyAdmin`; optional, warns without it |
| `address.sh` | key | `roles/cloudkms.admin` via the admin group |
| `grant.sh` | key, keeper project | admin group; `roles/iam.serviceAccountViewer` on the keeper project |
| `check.sh` | key project | `roles/viewer` and `roles/cloudkms.publicKeyViewer` |

## 2. config.env

```sh
cp config.env.example config.env
```

`KEEPER_SA` stays empty until part three exists. `config.env` is authoritative when present; CI supplies the same variables from the environment.

**Location.** Default `us`. One signature per weekly vote, so latency is irrelevant; multi-region buys availability; `us` matches where Base's sequencer is observed to run. Changing it changes the resource names and the record, so choose once.

## 3. setup.sh

```sh
sh/setup.sh
```

1. Enables `cloudkms.googleapis.com`.
2. Creates the key ring if absent.
3. Creates the key if absent: `asymmetric-signing`, `ec-sign-secp256k1-sha256`, `hsm`, destroy window `120d`. An existing key with other attributes is exit 10; a different window is exit 11 (immutable; use another `KEY` name).
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

Same key: no-op. Different key or address in the record: exit 18 unless `--force`. Files are written atomically.

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

`address` in `record/keeper.json` is `KEEPER`. `KEEPER` is immutable, so a new key means a new module; this repo never creates version 2.

Part one publishes the value it deploys in `script/keeper.json` so `check.sh` can compare it. Copying `record/keeper.json` satisfies the contract: `address` required, `version` optional but must match.

## 6. grant.sh

Set `KEEPER_SA` in `config.env`, then:

```sh
sh/grant.sh
```

Verifies the account exists, writes the full policy. Idempotent.

## 7. check.sh

```sh
sh/check.sh [../hydrex-conduit-executor]
```

Read-only. Every check runs; the exit code is the first failure's. A failed `gcloud` call is exit 1, never drift. Once `grant.sh` has run, `KEEPER_SA` must be set wherever `check.sh` runs.

| Exit | Meaning |
|---|---|
| 0 | all checks passed |
| 1 | gcloud call failed |
| 2 | config or usage error |
| 3 | missing tool or old gcloud |
| 10 | key not found, or key or version 1 attributes differ |
| 11 | destroy window is not 120 days |
| 12 | version 1 not `ENABLED` |
| 13 | version 1 missing or not the only version |
| 14 | live public key does not derive to the recorded address |
| 15 | key IAM policy differs from template |
| 16 | audit config lacks the KMS entry |
| 17 | relay `script/keeper.json` missing, malformed or different |
| 18 | `record/` missing or malformed |
| 19 | `iam.disableServiceAccountKeyCreation` not enforced |

### CI wiring

The workload identity pool lives in the keeper project (part three owns it). Until then:

```sh
gcloud iam workload-identity-pools create github --project=KEEPER_PROJECT --location=global
gcloud iam workload-identity-pools providers create-oidc github \
  --project=KEEPER_PROJECT --location=global --workload-identity-pool=github \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository \
  --attribute-condition="assertion.repository == 'leo-klima-agents/hydrex-keeper-key'"
```

Grant `roles/viewer` and `roles/cloudkms.publicKeyViewer` on the key project to
`principalSet://iam.googleapis.com/projects/KEEPER_PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/leo-klima-agents/hydrex-keeper-key`. No service account, no key. These two project-level bindings are the one thing here this repo does not write; part three owns them.

Repository variables: `KEY_PROJECT`, `KEEPER_PROJECT`, `LOCATION`, `KEY_RING`, `KEY`, `ADMIN_GROUP`, `KEEPER_SA`, `WIF_PROVIDER` (`projects/NUMBER/locations/global/workloadIdentityPools/github/providers/github`). Run the workflow once by hand.

A failed run reaches whoever GitHub notifies for workflow failures. Part three's alerting can take over later.

## Manual steps

1. **Hardware 2FA** on the admin group, enforced in Workspace.
2. **Audit log retention.** `_Default` keeps 30 days. Sink KMS logs to a locked bucket with 400+ days, in a project the admins do not own.
3. **Scheduled destruction.** Admins can schedule and cancel it within 120 days. Alert on `DestroyCryptoKeyVersion` and `UpdateCryptoKeyVersion`; `check.sh` fails with 12 the next Monday.
4. **Project ownership is the root.** An owner can re-grant `cloudkms.admin`. Key project owners must be the admin group or fewer, with no org-level owner reaching it. `check.sh` cannot assert this.

## Tests

```sh
test/run.sh            # goldens under dash
test/run.sh --update   # regenerate after an intended change
```

CI: `shellcheck -s sh`, `checkbashisms`, `sh -n`, `reuse lint`, goldens. Goldens hold every gcloud call, the exact policy JSON written, exit codes and files written. Only the scheduled `check` job touches GCP.

## Open decisions

1. Admin group membership, and whether key project owners are the same people.
2. Alerting target for `check.sh`. GitHub failure email is the default.

## Constraints

- `gcloud kms asymmetric-sign` hashes its input, so signature-recovery tests belong in part three.
- The address is the property of key version 1 alone. `check.sh` fails with 13 if another appears.

## License

MIT. REUSE compliant.
