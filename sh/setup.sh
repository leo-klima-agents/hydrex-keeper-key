#!/bin/sh
# sh/setup.sh - create and configure the key project. Idempotent.
#
# 1. Enable cloudkms.googleapis.com.
# 2. Create the key ring if absent.
# 3. Create the key if absent: asymmetric signing, secp256k1, HSM, 120-day
#    destroy window. Refuse to adopt an existing key with a different purpose,
#    algorithm or protection level.
# 4. Write the complete key IAM policy from policy/key.iam.json.tmpl.
# 5. Write the KMS Data Access audit config into the project IAM policy.
# 6. Enforce iam.disableServiceAccountKeyCreation on the project, if permitted.
# 7. Print the key version resource name and its state.
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
ring=$(gcloud kms keyrings list --project="$KEY_PROJECT" --location="$LOCATION" \
  --filter="name=$KEY_RING_NAME" --format=json |
  jq -r --arg name "$KEY_RING_NAME" '.[] | select(.name == $name) | .name')
if [ "$ring" = "$KEY_RING_NAME" ]; then
  log "key ring exists: $KEY_RING_NAME"
else
  log "creating key ring $KEY_RING_NAME"
  gcloud kms keyrings create "$KEY_RING_NAME"
fi

# 3. Key
log "== 3/7 key"
key=$(gcloud kms keys list --project="$KEY_PROJECT" --location="$LOCATION" --keyring="$KEY_RING" \
  --filter="name=$KEY_NAME" --format=json |
  jq -c --arg name "$KEY_NAME" '.[] | select(.name == $name)')
if [ -z "$key" ]; then
  log "creating key $KEY_NAME ($KEY_PURPOSE, $KEY_ALGORITHM, $KEY_PROTECTION, destroy window $DESTROY_WINDOW)"
  gcloud kms keys create "$KEY_NAME" \
    --purpose="$KEY_PURPOSE" \
    --default-algorithm="$KEY_ALGORITHM" \
    --protection-level="$KEY_PROTECTION" \
    --destroy-scheduled-duration="$DESTROY_WINDOW"
else
  purpose=$(printf '%s\n' "$key" | jq -r '.purpose')
  algorithm=$(printf '%s\n' "$key" | jq -r '.versionTemplate.algorithm')
  protection=$(printf '%s\n' "$key" | jq -r '.versionTemplate.protectionLevel')
  window=$(printf '%s\n' "$key" | jq -r '.destroyScheduledDuration // empty')
  if [ "$purpose" != "$KEY_PURPOSE_API" ] || [ "$algorithm" != "$KEY_ALGORITHM_API" ] || [ "$protection" != "$KEY_PROTECTION_API" ]; then
    die "$EXIT_KEY_ATTRIBUTES" "key $KEY_NAME exists with purpose=$purpose algorithm=$algorithm protectionLevel=$protection; expected $KEY_PURPOSE_API/$KEY_ALGORITHM_API/$KEY_PROTECTION_API. Not adopting it. Pick another KEY name or resolve by hand."
  fi
  log "key exists with the expected purpose, algorithm and protection level"
  if [ "$window" != "$DESTROY_WINDOW_API" ]; then
    log "destroy window is ${window:-unset}; setting $DESTROY_WINDOW"
    gcloud kms keys update "$KEY_NAME" --destroy-scheduled-duration="$DESTROY_WINDOW"
  fi
fi

# 4. Key IAM: the complete policy, admin group plus keeper (if configured).
log "== 4/7 key IAM"
[ -n "$KEEPER_SA" ] || log "KEEPER_SA is empty: the policy is the admin group alone until grant.sh"
set_iam_authoritative "$KEY_NAME" "$(render_key_policy)" kms keys

# 5. Audit config on the project. The project policy is not this repo's to own,
#    so bindings are kept as they are; the cloudkms.googleapis.com audit entry
#    is replaced in full by policy/audit.json.
log "== 5/7 audit logs"
project_policy=$(get_iam "$KEY_PROJECT" projects)
desired=$(printf '%s\n' "$project_policy" | jq --slurpfile audit "$POLICY_DIR/audit.json" \
  '.auditConfigs = ((.auditConfigs // []) | map(select(.service != $audit[0].service))) + $audit')
write_iam_if_changed "$KEY_PROJECT" "$project_policy" "$desired" projects

# 6. Org policy: no service-account keys can ever be minted in this project.
log "== 6/7 org policy"
effective=$(gcloud resource-manager org-policies describe "$SA_KEY_CONSTRAINT" \
  --project="$KEY_PROJECT" --effective --format=json 2>/dev/null || printf '{}')
if [ "$(printf '%s\n' "$effective" | jq -r '.booleanPolicy.enforced // false')" = "true" ]; then
  log "$SA_KEY_CONSTRAINT already enforced on $KEY_PROJECT (directly or inherited)"
elif gcloud resource-manager org-policies enable-enforce "$SA_KEY_CONSTRAINT" --project="$KEY_PROJECT"; then
  log "$SA_KEY_CONSTRAINT now enforced on $KEY_PROJECT"
else
  log "WARNING: could not enforce $SA_KEY_CONSTRAINT on $KEY_PROJECT (needs orgpolicy.policy.set). Ask an org admin to set it, or inherit it from the folder."
fi

# 7. Version 1
log "== 7/7 key version"
state=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json | jq -r '.state')
log "state: $state"
[ "$state" = "ENABLED" ] ||
  log "version 1 is $state; HSM generation takes a moment. Run address.sh once it is ENABLED."
printf '%s\n' "$KEY_VERSION_NAME"
