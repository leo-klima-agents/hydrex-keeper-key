#!/bin/sh
# Key project resources. Idempotent.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

[ $# -eq 0 ] || die "usage: ${0##*/}"
require_tools gcloud jq
load_config
make_tmp

log "== 1/6 APIs"
# shellcheck disable=SC2086
gcloud services enable $SERVICES --project="$KEY_PROJECT"

log "== 2/6 key ring"
ring=$(find_keyring)
if [ -n "$ring" ]; then
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
  read_key_attrs "$key"
  if [ "$purpose" != "$KEY_PURPOSE_API" ] || [ "$algorithm" != "$KEY_ALGORITHM_API" ] || [ "$protection" != "$KEY_PROTECTION_API" ]; then
    die "$KEY_NAME exists with purpose=$purpose algorithm=$algorithm protectionLevel=$protection; not adopting it"
  fi
  # destroyScheduledDuration cannot be updated.
  [ "$window" = "$DESTROY_WINDOW_API" ] ||
    die "$KEY_NAME has destroy window ${window:-unset}, expected $DESTROY_WINDOW_API; immutable, use another KEY name"
  log "exists: $KEY_NAME"
fi

log "== 4/6 key IAM"
[ -n "$KEEPER_SA" ] || log "KEEPER_SA empty: admin only"
key_policy=$(render_policy key.iam.json.tmpl)
set_iam "$KEY_NAME" "" "$key_policy" kms keys

log "== 5/6 audit logs"
set_audit

log "== 6/6 key version"
describe_version_1
log "state: $version_state"
[ "$version_state" = "ENABLED" ] || log "run address.sh once ENABLED"
printf '%s\n' "$KEY_VERSION_NAME"
