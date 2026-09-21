#!/bin/sh
# Key project resources. Idempotent.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

require_tools
load_config
make_tmp

log "== 1/7 API"
enabled=$(gcloud services list --enabled --project="$KEY_PROJECT" \
  --filter="config.name=$KMS_SERVICE" --format="value(config.name)")
if [ "$enabled" = "$KMS_SERVICE" ]; then
  log "$KMS_SERVICE enabled"
else
  log "enabling $KMS_SERVICE"
  gcloud services enable "$KMS_SERVICE" --project="$KEY_PROJECT"
fi

log "== 2/7 key ring"
ring=$(find_keyring)
if [ "$ring" = "$KEY_RING_NAME" ]; then
  log "exists: $KEY_RING_NAME"
else
  log "creating $KEY_RING_NAME"
  gcloud kms keyrings create "$KEY_RING_NAME"
fi

log "== 3/7 key"
key=$(find_key)
if [ -z "$key" ]; then
  log "creating $KEY_NAME"
  gcloud kms keys create "$KEY_NAME" \
    --purpose="$KEY_PURPOSE" \
    --default-algorithm="$KEY_ALGORITHM" \
    --protection-level="$KEY_PROTECTION" \
    --destroy-scheduled-duration="$DESTROY_WINDOW"
else
  read_key_attributes "$key" ||
    die "$EXIT_KEY_ATTRIBUTES" "$KEY_NAME exists with purpose=$purpose algorithm=$algorithm protectionLevel=$protection; not adopting it"
  # destroyScheduledDuration cannot be updated.
  [ "$window" = "$DESTROY_WINDOW_API" ] ||
    die "$EXIT_DESTROY_WINDOW" "$KEY_NAME has destroy window ${window:-unset}, expected $DESTROY_WINDOW_API; immutable, use another KEY name"
  log "exists: $KEY_NAME"
fi

log "== 4/7 key IAM"
[ -n "$KEEPER_SA" ] || log "KEEPER_SA empty: admin group only"
key_policy=$(render_key_policy)
set_iam_authoritative "$KEY_NAME" "$key_policy" kms keys

# Project bindings are kept; only the KMS audit entry is replaced.
log "== 5/7 audit logs"
project_policy=$(get_iam "$KEY_PROJECT" projects)
desired=$(printf '%s\n' "$project_policy" | jq --slurpfile audit "$POLICY_DIR/audit.json" \
  '.auditConfigs = ((.auditConfigs // []) | map(select(.service != $audit[0].service))) + $audit')
write_iam_if_changed "$KEY_PROJECT" "$project_policy" "$desired" projects

log "== 6/7 org policy"
if org_policy_enforced 2>"$TMP/orgpolicy.err"; then
  log "$SA_KEY_CONSTRAINT enforced"
elif [ -s "$TMP/orgpolicy.err" ]; then
  log "WARNING: cannot read $SA_KEY_CONSTRAINT: $(cat "$TMP/orgpolicy.err")"
elif gcloud resource-manager org-policies enable-enforce "$SA_KEY_CONSTRAINT" --project="$KEY_PROJECT" >/dev/null 2>"$TMP/orgpolicy.err"; then
  log "$SA_KEY_CONSTRAINT now enforced"
else
  log "WARNING: cannot enforce $SA_KEY_CONSTRAINT (needs orgpolicy.policy.set): $(cat "$TMP/orgpolicy.err")"
fi

log "== 7/7 key version"
describe_version_1
log "state: $version_state"
[ "$version_state" = "ENABLED" ] || log "run address.sh once ENABLED"
printf '%s\n' "$KEY_VERSION_NAME"
