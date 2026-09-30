#!/bin/sh
# Creates the key ring, the HSM key, its IAM policy, the KMS audit logs and the alert in the key project. Idempotent.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

[ $# -eq 0 ] || die "usage: ${0##*/}"
require_tools gcloud jq
load_config
make_tmp

log "== 1/7 APIs"
# shellcheck disable=SC2086
gcloud services enable $SERVICES --project="$KEY_PROJECT"

log "== 2/7 key ring"
ring=$(find_keyring)
if [ -n "$ring" ]; then
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
  read_key_attrs "$key"
  if [ "$purpose" != "$KEY_PURPOSE_API" ] || [ "$algorithm" != "$KEY_ALGORITHM_API" ] || [ "$protection" != "$KEY_PROTECTION_API" ]; then
    die "$KEY_NAME exists with purpose=$purpose algorithm=$algorithm protectionLevel=$protection; not adopting it"
  fi
  # The destroy window cannot be changed after creation.
  [ "$window" = "$DESTROY_WINDOW_API" ] ||
    die "$KEY_NAME has destroy window ${window:-unset}, expected $DESTROY_WINDOW_API; use another KEY name"
  log "exists: $KEY_NAME"
fi

log "== 4/7 key IAM"
[ -n "$KEEPER_SA" ] || log "KEEPER_SA empty: admin only"
key_policy=$(render_policy key.iam.json.tmpl)
set_iam "$KEY_NAME" "" "$key_policy" kms keys

log "== 5/7 audit logs"
set_audit

log "== 6/7 alert"
channel=$(find_channel "$KEY_PROJECT")
if [ -n "$channel" ]; then
  log "exists: $channel"
else
  log "creating email channel for $ALERT_EMAIL"
  channel=$(gcloud beta monitoring channels create --project="$KEY_PROJECT" --display-name="$KEY_RING alerts" \
    --type=email --channel-labels="email_address=$ALERT_EMAIL" --format="value(name)")
fi
# ensure_alert PROJECT NAME FILE: creates the alert policy in FILE unless PROJECT has one named NAME.
ensure_alert() {
  alert=$(find_alert "$1" "$2")
  if [ -n "$alert" ]; then
    log "exists: $2"
  else
    log "creating alert policy: $2"
    gcloud monitoring policies create --project="$1" --policy-from-file="$3" >/dev/null
  fi
}
# A log-based condition needs a notification rate limit.
jq -n --arg name "$ALERT_NAME" --arg filter "$ALERT_FILTER" --arg channel "$channel" --arg ring "$KEY_RING_NAME" '{
  displayName: $name,
  combiner: "OR",
  conditions: [{displayName: "admin activity under the key ring", conditionMatchedLog: {filter: $filter}}],
  alertStrategy: {notificationRateLimit: {period: "300s"}},
  notificationChannels: [$channel],
  documentation: {
    mimeType: "text/markdown",
    content: "Something under \($ring) changed: a key, a key version or an IAM policy. Read the audit log entry; a scheduled destruction can be cancelled for 120 days."
  }
}' >"$TMP/alert.json"
ensure_alert "$KEY_PROJECT" "$ALERT_NAME" "$TMP/alert.json"

log "== 7/7 key version"
describe_version_1
log "state: $version_state"
[ "$version_state" = "ENABLED" ] || log "run address.sh once ENABLED"
printf '%s\n' "$KEY_VERSION_NAME"
