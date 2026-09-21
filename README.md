# hydrex-keeper-key

Part two of three. Part one, `hydrex-conduit-executor`, is an immutable Safe module whose `KEEPER` immutable is an EOA address. Part three, the keeper service, runs as a Cloud Run job in its own GCP project and signs with that key. This repo creates the key and everything around it in Google Cloud KMS, proves which Ethereum address it has, records that address for part one's `script/Deploy.s.sol`, and detects drift afterwards.

It holds no secrets. The private key never leaves the HSM. The repo commits only public material and resource names.

## The model

Two GCP projects.

- **Key project** holds one key ring and one key, nothing else. Key administration is `roles/cloudkms.admin` on the key for a small human group behind hardware 2FA. Nothing in CI ever holds it. Data Access audit logs for KMS are on. The key's destruction window is the 120-day maximum.
- **Keeper project** holds the runtime (part three) and receives exactly one cross-project grant: `roles/cloudkms.signer` on the key (plus `roles/cloudkms.publicKeyViewer`, so it can read its own address) to the Cloud Run job's service account.

IAM is always set authoritatively. Every script writes the complete policy it expects and never adds a binding to whatever is there. There is one policy template, `policy/key.iam.json.tmpl`, and `setup.sh` and `grant.sh` both write it in full.

Tooling is POSIX shell over `gcloud`, chosen over OpenTofu for this project on purpose: five resources, no state bucket, no provider supply chain, and every API call readable in the script. Part three will use OpenTofu. This repo stays the reference for what the key project must look like.

## Layout

```
README.md                    this file
config.env.example           every input, documented; copy to config.env (gitignored)
sh/lib.sh                    config loading, dependency and version checks, logging, authoritative IAM helper
sh/setup.sh                  key project resources, idempotent
sh/grant.sh                  the one cross-project binding, idempotent
sh/address.sh                public key -> Ethereum address, writes record/
sh/check.sh                  live state vs record/ and vs the expected IAM, distinct exit codes
policy/key.iam.json.tmpl     the complete expected IAM policy of the key, templated from config
policy/audit.json            the auditConfigs entry for cloudkms.googleapis.com
record/keeper.pem            SPKI public key, as gcloud returned it (written by address.sh)
record/keeper.json           key resource name, version, algorithm, protection level, address, sha256 of the PEM
test/fake-gcloud             gcloud stub that records calls; test/golden/*.txt are the expected call sequences
test/run.sh                  runs every script under dash against the stub and diffs the goldens
.github/workflows/ci.yml     lint and golden tests on every push; check.sh weekly via Workload Identity Federation
```

## 1. Prerequisites

Tools on the admin machine: `gcloud` (470.0.0 or newer, pinned in `sh/lib.sh`) and `jq` for every script; `openssl` and `cast` from [Foundry](https://getfoundry.sh) for `address.sh` and `check.sh` only, since only those derive the address. Scripts run under any POSIX `sh` with the usual utilities (`sed`, `awk`, `grep`, `od`, `tail`); CI runs them under `dash`.

Operator IAM, for the human running the scripts:

| Script | Where | Role |
|---|---|---|
| `setup.sh` | key project | `roles/owner`, or the trio `roles/serviceusage.serviceUsageAdmin`, `roles/cloudkms.admin`, `roles/resourcemanager.projectIamAdmin` |
| `setup.sh` step 6 | organisation or folder | `roles/orgpolicy.policyAdmin`, optional; without it the step reports and moves on |
| `address.sh` | key | `roles/cloudkms.admin` through the admin group |
| `grant.sh` | key, and keeper project | `roles/cloudkms.admin` through the admin group; `roles/iam.serviceAccountViewer` on the keeper project |
| `check.sh` | key project | `roles/viewer` and `roles/cloudkms.publicKeyViewer`, project level |

Run `setup.sh` as a member of the admin group who is also an owner of the key project. Owners are the real root of trust here (see "Manual steps").

## 2. Fill config.env

```sh
cp config.env.example config.env
"$EDITOR" config.env
```

Every value is documented in the example. `KEEPER_SA` stays empty until part three has created the job's service account.

**Location.** The default is the multi-region `us`. The keeper signs one transaction per weekly vote, so KMS latency and per-region quota are irrelevant. Multi-region keys are served from several regions, which buys availability over a single region at no cost to this workload. `us` also matches where Base's sequencer is observed to run, so the signer and the chain endpoint are unlikely to be split across an ocean. Any location works; changing it changes the resource names and therefore the record, so choose once.

## 3. Run setup.sh

```sh
sh/setup.sh
```

Idempotent. In order:

1. Enables `cloudkms.googleapis.com`.
2. Creates the key ring if absent.
3. Creates the key if absent: purpose `asymmetric-signing`, algorithm `ec-sign-secp256k1-sha256`, protection level `hsm`, destroy window `120d`. If a key of that name exists with a different purpose, algorithm or protection level, it stops with exit code 10 rather than adopting it. If the destroy window differs it stops with exit code 11: the window is immutable on a KMS key, so the only fix is a new key under another `KEY` name.
4. Renders `policy/key.iam.json.tmpl` and writes it to the key with `set-iam-policy` using the live etag. Before `grant.sh` the policy is the admin group as `roles/cloudkms.admin` and nothing else. Once `KEEPER_SA` is in config, the keeper bindings are included, so running `setup.sh` after `grant.sh` never removes the grant.
5. Merges `policy/audit.json` into the project IAM policy: the `cloudkms.googleapis.com` audit entry is replaced in full (ADMIN_READ, DATA_READ, DATA_WRITE); the project's bindings are left alone, since the project policy is not this repo's to own.
6. Enforces `iam.disableServiceAccountKeyCreation` on the project, if permitted. It reads the effective policy first and writes only when the read succeeded and says not enforced. If the read or the write fails it prints gcloud's message as a warning and continues; ask an org admin to set it or inherit it from the folder.
7. Prints the key version resource name and its state. HSM generation takes a moment; version 1 may be `PENDING_GENERATION` for a few seconds.

Confirm in the console: one key ring, one key, one version, HSM, secp256k1, destroy window 120 days, and under the key's Permissions tab exactly the admin group. Under IAM > Audit Logs, Cloud KMS has all three log types on.

No writes happen when the live state already matches; a second run is all reads.

## 4. Run address.sh and commit record/

```sh
sh/address.sh
git add record/keeper.pem record/keeper.json
git commit -m "record: keeper key version 1"
```

Prints the checksummed address and writes `record/`. The address is the property of key version 1 alone.

Re-running it against the same key writes nothing and exits 0, judged on the files on disk, so a deleted or edited `keeper.pem` is regenerated. If `record/keeper.json` already exists and names a different key version or address, it refuses with exit 18 rather than overwrite the record that `check.sh` and part one's `KEEPER` are pinned to. `sh/address.sh --force` overrides that, for the case where a new key and therefore a new module are intended. A record for the same key and address whose PEM bytes differ, which can only be a formatting change in gcloud's output, is refreshed without ceremony.

### The derivation, by hand

Reviewers should be able to reproduce the address without trusting the script.

```sh
gcloud kms keys versions get-public-key \
  projects/KEY_PROJECT/locations/us/keyRings/hydrex-keeper/cryptoKeys/keeper/cryptoKeyVersions/1 \
  --output-file=keeper.pem

# It is a secp256k1 public key. The pub: field is 65 bytes: 0x04 then X then Y.
openssl pkey -pubin -in keeper.pem -text -noout

# PEM -> DER. A secp256k1 SubjectPublicKeyInfo is 88 bytes: a 24-byte header
# (SEQUENCE, id-ecPublicKey, secp256k1 OID, BIT STRING, 0x04) then X||Y.
openssl pkey -pubin -in keeper.pem -outform DER -out keeper.der
wc -c keeper.der                                       # 88

# The last 64 bytes are X||Y.
XY=$(tail -c 64 keeper.der | od -An -v -tx1 | tr -d ' \n')

# keccak256(X||Y); the address is the last 20 bytes.
HASH=$(cast keccak "0x$XY")
cast to-check-sum-address "0x$(printf '%s' "$HASH" | tail -c 40)"
```

Compare with `address` in `record/keeper.json`, and `sha256sum keeper.pem` with `pemSha256`. The golden test `test/golden/address.txt` runs exactly this pipeline over the secp256k1 generator point (private key 1) and gets `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`, the address every Ethereum toolchain agrees on for that key.

## 5. Hand the address to part one

`address` in `record/keeper.json` is `KEEPER` in `hydrex-conduit-executor/script/Deploy.s.sol`. Deploy the module. `KEEPER` is immutable there, so a new key means a new module; that is by design, and it is why this repo never creates a second key version.

## 6. Run grant.sh once part three exists

When part three has created the Cloud Run job's service account, put its email in `KEEPER_SA` in `config.env`, then:

```sh
sh/grant.sh
```

It checks the account exists in the keeper project, then writes the complete key policy: admin group as `roles/cloudkms.admin`, keeper account as `roles/cloudkms.signer` and `roles/cloudkms.publicKeyViewer`. Running it twice is a no-op. This is the only cross-project grant the keeper project receives.

Commit nothing; the grant is visible in the live policy and asserted by `check.sh`.

## 7. Enable the weekly check

`check.sh` is the only script CI runs against the real cloud. It is read-only, runs weekly (Monday 09:00 UTC) and on demand, authenticates through Workload Identity Federation and stores no secret.

```sh
sh/check.sh                       # against the live key project
sh/check.sh ../hydrex-conduit-executor   # also compares KEEPER in script/Deploy.s.sol
```

It re-derives the address from the live key and compares it with `record/`, asserts version 1 is `ENABLED` and is the only version, that the key's purpose, algorithm, protection level and destroy window are unchanged, that version 1's own algorithm and protection level are secp256k1 and HSM (the key's template is mutable; the version's material is not), that the key's IAM policy equals the rendered template exactly, and that the project audit config still contains the KMS entry. Every check runs; every failure is printed; the exit code is the first failure's. A failed `gcloud` call is exit 1 with gcloud's message, never reported as drift; the one exception is a `NOT_FOUND` on the key itself, which is exit 10. When version 1 is not an `ENABLED` secp256k1 HSM version the address check is skipped, since the derivation does not apply, and exits 10, 12 or 13 already name the problem.

The relay comparison looks for the one `KEEPER = 0x…` assignment in `script/Deploy.s.sol` (also `address(0x…)` or `payable(0x…)`) after a single pass that removes `//` and `/* */` comments and string literals and joins lines. A commented-out old value, a URL inside a comment or a string, a `KEEPER_*` identifier, a `KEEPER ==` comparison or a formatter-wrapped assignment do not confuse it. Two different assignments are exit 17 as well; part one must keep exactly one.

`check.sh` renders the expected policy from your config, so once `grant.sh` has run, `KEEPER_SA` must be set wherever `check.sh` runs (config.env locally, the repository variable in CI), or the live grant reads as drift with exit 15.

| Exit | Meaning |
|---|---|
| 0 | all checks passed |
| 1 | a gcloud call failed |
| 2 | config missing, incomplete or inconsistent; bad usage |
| 3 | a required tool is missing or gcloud is older than the pinned minimum |
| 10 | key not found (`NOT_FOUND` from KMS), or purpose, algorithm or protection level differ, on the key or on version 1 |
| 11 | destroy window is not 120 days (immutable; `setup.sh` will not adopt such a key) |
| 12 | version 1 is not `ENABLED` |
| 13 | a version other than 1 exists, or the only version is not version 1 |
| 14 | live public key does not derive to the recorded address |
| 15 | key IAM policy differs from the rendered template |
| 16 | project audit config lacks the KMS entry |
| 17 | `KEEPER` in the relay repo differs from the record |
| 18 | `record/` missing or malformed |

The same codes are used by `setup.sh` (2, 3, 10, 11) and `address.sh` (2, 3, 10, 12, 18).

### Wiring the workflow

The workload identity pool lives in the keeper project, where part three's OpenTofu will own it; nothing is added to the key project. Until part three exists, by hand:

```sh
gcloud iam workload-identity-pools create github \
  --project=KEEPER_PROJECT --location=global
gcloud iam workload-identity-pools providers create-oidc github \
  --project=KEEPER_PROJECT --location=global --workload-identity-pool=github \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository \
  --attribute-condition="assertion.repository == 'leo-klima-agents/hydrex-keeper-key'"
```

The workflow then acts directly as the federated principal, with no service account and no key:

```
principalSet://iam.googleapis.com/projects/KEEPER_PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/leo-klima-agents/hydrex-keeper-key
```

Grant that principal `roles/viewer` and `roles/cloudkms.publicKeyViewer` on the key project, at project level. These two project-level bindings are the one thing in the key project this repo does not write authoritatively; part three owns them. The key's own policy stays exactly the template, and `check.sh` asserts that.

Set these repository variables (Settings > Secrets and variables > Actions > Variables; they are public material, not secrets): `KEY_PROJECT`, `KEEPER_PROJECT`, `LOCATION`, `KEY_RING`, `KEY`, `ADMIN_GROUP`, `KEEPER_SA`, and `WIF_PROVIDER` as `projects/KEEPER_PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/github`. `sh/lib.sh` takes configuration from the environment only when there is no `config.env`, which is how CI runs without one. When the file exists it is authoritative, so a `KEY` or `LOCATION` left over in an operator's shell cannot point a script at another key.

Then run the workflow once by hand (Actions > ci > Run workflow) and confirm the `check` job is green.

A failed run reaches whoever GitHub notifies for workflow failures on this repo, by default the person who last touched the workflow. That is the zero-cost alerting target; part three's alerting can take it over later.

## Manual steps

Things no script can do, in the order they matter.

1. **Hardware 2FA on the admin group.** In Google Workspace admin, enforce 2-Step Verification with security keys only for the organisational unit or group the admins belong to. Nothing in the key's policy stops a phished admin; this does.
2. **Audit log retention.** Data Access logs for KMS land in the project's `_Default` log bucket, which keeps 30 days. Create a sink to a dedicated log bucket with a longer retention, 400 days or more, locked, ideally in a project the admin group does not own, so an admin cannot delete the record of what they did.
3. **Who can cancel a scheduled destruction.** Anyone with `cloudkms.cryptoKeyVersions.destroy` can schedule one and anyone with `cloudkms.cryptoKeyVersions.restore` can cancel it within the 120-day window; both are in `roles/cloudkms.admin`, so the admin group is both. The window only helps if someone notices. Create a log-based alert on `DestroyCryptoKeyVersion` and `UpdateCryptoKeyVersion` (state changes) for the key, routed to a channel the admins read. `check.sh` will also fail with exit 12 the next Monday.
4. **Ownership of the key project is the real root.** A project owner can always re-grant `roles/cloudkms.admin` to anyone, whatever this repo writes. The owners of the key project must therefore be the same two or three humans as the admin group, or fewer, and nobody else: no organisation-level `roles/owner` or `roles/resourcemanager.projectIamAdmin` that reaches the project. Review the effective policy with `gcloud projects get-ancestors-iam-policy`. Note `check.sh` does not and cannot assert this from a viewer role.

## Testing and CI

```sh
test/run.sh              # every script under dash against test/fake-gcloud, diffed against test/golden
test/run.sh --update     # regenerate goldens after an intended change
```

CI runs `shellcheck -s sh`, `checkbashisms`, `sh -n`, `reuse lint`, and the golden tests on every push and pull request. `test/fake-gcloud` answers from canned state per scenario and appends each call to a log; the log, the exit code, and any files written are compared with `test/golden/<case>.txt`. The scenarios cover a fresh project, an already-configured one, repairs, a foreign key, a key with the wrong destroy window, each drift `check.sh` detects, the pre-grant and post-grant states, the record refusal, refresh and `--force`, a malformed record, and relay files with decoy or ambiguous `KEEPER` lines. Where a script writes a policy, the golden holds the exact JSON it would send, including the etag, so a change to what the scripts would do shows up as a diff in review. Only the scheduled `check` job has GCP access.

## Decisions remaining

1. **Admin group membership.** Who the two or three humans are, and whether the key project's owners are the same people. Everything else about the key's trust boundary follows from this.
2. **Alerting target for `check.sh`.** GitHub's built-in failure email is the zero-cost default in use; part three's alerting could take it over later.

## Constraints carried over

- `gcloud kms asymmetric-sign` hashes its input itself, so an end-to-end check that KMS signatures recover to the recorded address belongs in part three's signer tests, not here.
- The address is the property of key version 1 alone. This repo never creates a second version, and `check.sh` fails with exit 13 if one appears.

## License

MIT. See `LICENSE`; the repo is [REUSE](https://reuse.software) compliant.
