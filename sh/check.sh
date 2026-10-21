#!/bin/sh
# Compares the live key of each role, the alert and KEEPER_SA with config.env, policy/ and record/. Read-only; runs
# every check, exits 1 if any failed.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

[ $# -eq 0 ] || die "usage: ${0##*/}"
require_tools gcloud jq openssl
require_keccak
load_config
make_tmp

failed=0
fail() {
  log "FAIL: $*"
  failed=1
}
ok() { log "ok: $*"; }
# expect LABEL ACTUAL EXPECTED
expect() {
  if [ "$2" = "$3" ]; then ok "$1 is $3"; else fail "$1 is ${2:-unset}, expected $3"; fi
}
# expect_policy LABEL LIVE TEMPLATE
expect_policy() {
  if policy_differs "$2" "$(render_policy "$3")"; then
    fail "$1 IAM policy differs from template"
    show_policy_diff
  else
    ok "$1 IAM policy matches template"
  fi
}

# check_key: the role's record, key, versions, address of version 1 and key IAM policy.
check_key() {
  # Record: a problem fails, and skips the comparison with the live address.
  record_ok=yes
  read_record
  if [ -z "$recorded_address" ] || [ -z "$recorded_version" ]; then
    fail "$ROLE record lacks address or version"
    record_ok=no
  elif [ "$recorded_version" != "$KEY_VERSION_NAME" ]; then
    fail "$ROLE record is for $recorded_version, config is $KEY_VERSION_NAME"
    record_ok=no
  elif [ ! -f "$RECORD_PEM" ]; then
    fail "$RECORD_PEM missing; run address.sh"
    record_ok=no
  elif ! record_pem_address=$(derive_address "$RECORD_PEM"); then
    fail "$ROLE.pem is not a secp256k1 public key"
    record_ok=no
  elif [ "$record_pem_address" != "$recorded_address" ]; then
    fail "$ROLE.pem derives to $record_pem_address, record says $recorded_address"
    record_ok=no
  else
    ok "$ROLE record is consistent"
  fi

  # Key
  key=$(find_key)
  [ -n "$key" ] || die "$KEY_NAME not found; run setup.sh"
  read_key_attrs "$key"
  expect "$ROLE key purpose" "$purpose" "$KEY_PURPOSE_API"
  expect "$ROLE key algorithm" "$algorithm" "$KEY_ALGORITHM_API"
  expect "$ROLE key protection level" "$protection" "$KEY_PROTECTION_API"
  expect "$ROLE key destroy window" "$window" "$DESTROY_WINDOW_API"

  # Versions: version 1 alone, enabled and of the expected kind.
  versions=$(gcloud kms keys versions list --project="$KEY_PROJECT" --location="$LOCATION" \
    --keyring="$KEY_RING" --key="$KEY" --format=json) || die "cannot list versions of $KEY_NAME"
  require_json "$versions" "version list of $KEY_NAME"
  expect "$ROLE key versions" "$(json_field "$versions" '[.[].name | split("/") | last] | join(" ")')" 1
  version1=$(printf '%s\n' "$versions" | jq -c --arg name "$KEY_VERSION_NAME" 'first(.[] | select(.name == $name)) // empty')
  version_state='' version_algorithm=''
  if [ -z "$version1" ]; then
    fail "$ROLE version 1 missing"
  else
    read_version_attrs "$version1"
    expect "$ROLE version 1 state" "$version_state" ENABLED
    expect "$ROLE version 1 algorithm" "$version_algorithm" "$KEY_ALGORITHM_API"
    expect "$ROLE version 1 protection level" "$version_protection" "$KEY_PROTECTION_API"
  fi

  # Address
  if [ "$record_ok" = yes ] && [ "$version_state" = ENABLED ] && [ "$version_algorithm" = "$KEY_ALGORITHM_API" ]; then
    pem=$TMP/live.pem
    gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
    live_address=$(derive_address "$pem")
    expect "address of $ROLE version 1" "$live_address" "$recorded_address"
  else
    log "skipping the $ROLE address check"
  fi

  # Key IAM
  key_policy=$(get_iam "$KEY_NAME" "" kms keys)
  expect_policy "$ROLE key" "$key_policy" key.iam.json.tmpl
}

# A record without a key in config.env would go unchecked.
if [ -z "$PROPOSER_KEY" ] && { [ -f "$RECORD_DIR/proposer.json" ] || [ -f "$RECORD_DIR/proposer.pem" ]; }; then
  fail "$RECORD_DIR has a proposer record but PROPOSER_KEY is not set"
fi

# A missing record stops the check before any call.
for role in $ROLES; do
  use_key "$role"
  read_record
done
for role in $ROLES; do
  use_key "$role"
  check_key
done

# Audit config
project_policy=$(get_iam "$KEY_PROJECT" "" projects)
if audit_differs "$project_policy"; then
  fail "audit config for $KMS_SERVICE differs from policy/audit.json"
  show_policy_diff
else
  ok "audit config for $KMS_SERVICE matches policy/audit.json"
fi

# Keeper service account
if [ -z "$KEEPER_SA" ]; then
  log "KEEPER_SA is empty: skipping its checks"
else
  sa_keys=$(gcloud iam service-accounts keys list --iam-account="$KEEPER_SA" --managed-by=user --format=json) ||
    die "cannot list keys of $KEEPER_SA"
  require_json "$sa_keys" "key list of $KEEPER_SA"
  sa_key_ids=$(json_field "$sa_keys" '[.[].name | split("/") | last] | join(" ")')
  if [ -z "$sa_key_ids" ]; then ok "$KEEPER_SA has no user-managed keys"; else fail "$KEEPER_SA has user-managed keys: $sa_key_ids"; fi
  sa_policy=$(get_iam "$KEEPER_SA" "--project=$KEEPER_PROJECT" iam service-accounts)
  sa_bindings=$(json_field "$sa_policy" '[.bindings[]? | "\(.role):\(.members | join(","))"] | join(" ")')
  if [ -z "$sa_bindings" ]; then ok "nobody can act as $KEEPER_SA"; else fail "$KEEPER_SA has IAM bindings: $sa_bindings"; fi
fi

# Alert
channel=$(find_channel "$KEY_PROJECT")
[ -n "$channel" ] || fail "no email channel for $ALERT_EMAIL"
# expect_alert PROJECT NAME FILTER
expect_alert() {
  alert=$(find_alert "$1" "$2")
  if [ -z "$alert" ]; then
    fail "alert policy \"$2\" missing"
    return 0
  fi
  expect "\"$2\" enabled" "$(json_field "$alert" '.enabled | tostring')" "true"
  if [ -n "$channel" ] && [ "$(json_field "$alert" ".notificationChannels | index(\"$channel\") != null")" = true ]; then
    ok "\"$2\" notifies $ALERT_EMAIL"
  else
    fail "\"$2\" does not notify $ALERT_EMAIL"
  fi
  expect "\"$2\" filter" "$(json_field "$alert" '.conditions[0] | (.conditionThreshold // .conditionMatchedLog).filter')" "$3"
}
expect_alert "$KEY_PROJECT" "$ALERT_NAME" "$ALERT_FILTER"

[ "$failed" -ne 0 ] || log "all checks passed"
exit "$failed"
