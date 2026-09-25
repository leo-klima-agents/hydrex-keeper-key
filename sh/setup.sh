#!/bin/sh
# Key project resources. Idempotent.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

require_tools
load_config
make_tmp

log "== 1/6 KMS API"
gcloud services enable "$KMS_SERVICE" --project="$KEY_PROJECT"

log "== 2/6 key ring"
ring=$(find_keyring)
if [ "$ring" = "$KEY_RING_NAME" ]; then
  log "exists: $KEY_RING_NAME"
else
  log "creating $KEY_RING_NAME"
  gcloud kms keyrings create "$KEY_RING_NAME"
fi

log "== 3/6 key"
key=$(find_key)
if [ -z "$key" ]; then
  log "creating $KEY_NAME"
  gcloud kms keys create "$KEY_NAME" \
    --purpose="$KEY_PURPOSE" \
    --default-algorithm="$KEY_ALGORITHM" \
    --protection-level="$KEY_PROTECTION" \
    --destroy-scheduled-duration="$DESTROY_WINDOW"
else
  read_key_attrs "$key" ||
    die "$KEY_NAME exists with purpose=$purpose algorithm=$algorithm protectionLevel=$protection; not adopting it"
  # destroyScheduledDuration cannot be updated.
  [ "$window" = "$DESTROY_WINDOW_API" ] ||
    die "$KEY_NAME has destroy window ${window:-unset}, expected $DESTROY_WINDOW_API; immutable, use another KEY name"
  log "exists: $KEY_NAME"
fi

log "== 4/6 key IAM"
[ -n "$KEEPER_SA" ] || log "KEEPER_SA empty: admin only"
key_policy=$(render_key_policy)
set_iam_authoritative "$KEY_NAME" "$key_policy" kms keys

# Project bindings are kept; only the KMS audit entry is replaced.
log "== 5/6 audit logs"
project_policy=$(get_iam "$KEY_PROJECT" projects)
desired=$(printf '%s\n' "$project_policy" | jq --slurpfile audit "$POLICY_DIR/audit.json" \
  '.auditConfigs = ((.auditConfigs // []) | map(select(.service != $audit[0].service))) + $audit')
write_iam_if_changed "$KEY_PROJECT" "$project_policy" "$desired" projects

log "== 6/6 key version"
describe_version_1
log "state: $version_state"
[ "$version_state" = "ENABLED" ] || log "run address.sh once ENABLED"
printf '%s\n' "$KEY_VERSION_NAME"
