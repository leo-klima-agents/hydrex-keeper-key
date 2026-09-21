#!/bin/sh
# sh/setup.sh - create and configure the key project. Idempotent.
#
# 1. Enable cloudkms.googleapis.com.
# 2. Create the key ring if absent.
# 3. Create the key if absent: asymmetric signing, secp256k1, HSM, 120-day
#    destroy window. Refuse to adopt an existing key with a different purpose,
#    algorithm, protection level or destroy window (the window is immutable).
# 4. Write the complete key IAM policy from policy/key.iam.json.tmpl.
# 5. Write the KMS Data Access audit config into the project IAM policy.
# 6. Enforce iam.disableServiceAccountKeyCreation on the project, if permitted.
# 7. Print the key version resource name and its state. Stops with exit 10 if
#    version 1's own algorithm or protection level are not the expected ones
#    (the key's template is mutable; the version's material is not).
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

require_tools
load_config
make_tmp

# 1. API
log "== 1/7 API"
enabled=$(gcloud services list --enabled --project="$KEY_PROJECT" \
  --filter="config.name=$KMS_SERVICE" --format="value(config.name)")
if [ "$enabled" = "$KMS_SERVICE" ]; then
  log "$KMS_SERVICE already enabled on $KEY_PROJECT"
else
  log "enabling $KMS_SERVICE on $KEY_PROJECT"
  gcloud services enable "$KMS_SERVICE" --project="$KEY_PROJECT"
fi

# 2. Key ring
log "== 2/7 key ring"
ring=$(find_keyring)
if [ "$ring" = "$KEY_RING_NAME" ]; then
  log "key ring exists: $KEY_RING_NAME"
else
  log "creating key ring $KEY_RING_NAME"
  gcloud kms keyrings create "$KEY_RING_NAME"
fi

# 3. Key
log "== 3/7 key"
key=$(find_key)
if [ -z "$key" ]; then
  log "creating key $KEY_NAME ($KEY_PURPOSE, $KEY_ALGORITHM, $KEY_PROTECTION, destroy window $DESTROY_WINDOW)"
  gcloud kms keys create "$KEY_NAME" \
    --purpose="$KEY_PURPOSE" \
    --default-algorithm="$KEY_ALGORITHM" \
    --protection-level="$KEY_PROTECTION" \
    --destroy-scheduled-duration="$DESTROY_WINDOW"
else
  if ! read_key_attributes "$key"; then
    die "$EXIT_KEY_ATTRIBUTES" "key $KEY_NAME exists with purpose=$purpose algorithm=$algorithm protectionLevel=$protection; expected $KEY_PURPOSE_API/$KEY_ALGORITHM_API/$KEY_PROTECTION_API. Not adopting it. Pick another KEY name or resolve by hand."
  fi
  log "key exists with the expected purpose, algorithm and protection level"
  # destroyScheduledDuration is immutable on a CryptoKey; there is no update.
  [ "$window" = "$DESTROY_WINDOW_API" ] ||
    die "$EXIT_DESTROY_WINDOW" "key $KEY_NAME has destroy window ${window:-unset}, expected $DESTROY_WINDOW_API ($DESTROY_WINDOW). The window is immutable; a key with the right window must be created under another KEY name."
fi

# 4. Key IAM: the complete policy, admin group plus keeper (if configured).
log "== 4/7 key IAM"
[ -n "$KEEPER_SA" ] || log "KEEPER_SA is empty: the policy is the admin group alone until grant.sh"
key_policy=$(render_key_policy)
set_iam_authoritative "$KEY_NAME" "$key_policy" kms keys

# 5. Audit config on the project. The project policy is not this repo's to own,
#    so bindings are kept as they are; the cloudkms.googleapis.com audit entry
#    is replaced in full by policy/audit.json.
log "== 5/7 audit logs"
project_policy=$(get_iam "$KEY_PROJECT" projects)
desired=$(printf '%s\n' "$project_policy" | jq --slurpfile audit "$POLICY_DIR/audit.json" \
  '.auditConfigs = ((.auditConfigs // []) | map(select(.service != $audit[0].service))) + $audit')
write_iam_if_changed "$KEY_PROJECT" "$project_policy" "$desired" projects

# 6. Org policy: no service-account keys can ever be minted in this project.
#    Read first; write only when the read succeeded and says not enforced.
log "== 6/7 org policy"
if org_policy_enforced 2>"$TMP/orgpolicy.err"; then
  log "$SA_KEY_CONSTRAINT already enforced on $KEY_PROJECT (directly or inherited)"
elif [ -s "$TMP/orgpolicy.err" ]; then
  log "WARNING: could not read the effective $SA_KEY_CONSTRAINT policy on $KEY_PROJECT: $(cat "$TMP/orgpolicy.err")"
  log "WARNING: not attempting to set it. Check by hand or re-run once the read works."
elif gcloud resource-manager org-policies enable-enforce "$SA_KEY_CONSTRAINT" --project="$KEY_PROJECT" >/dev/null 2>"$TMP/orgpolicy.err"; then
  log "$SA_KEY_CONSTRAINT now enforced on $KEY_PROJECT"
else
  log "WARNING: could not enforce $SA_KEY_CONSTRAINT on $KEY_PROJECT: $(cat "$TMP/orgpolicy.err")"
  log "WARNING: needs orgpolicy.policy.set. Ask an org admin to set it, or inherit it from the folder."
fi

# 7. Version 1
log "== 7/7 key version"
describe_version_1
log "state: $version_state"
[ "$version_state" = "ENABLED" ] ||
  log "version 1 is $version_state; HSM generation takes a moment. Run address.sh once it is ENABLED."
printf '%s\n' "$KEY_VERSION_NAME"
