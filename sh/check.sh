#!/bin/sh
# sh/check.sh [RELAY_REPO_DIR] - live state vs record/ and vs the expected IAM.
#
# Read-only. Runs every check, reports each failure, and exits with the code
# of the first one (see lib.sh for the codes). With RELAY_REPO_DIR, also
# confirms KEEPER in script/Deploy.s.sol matches the record.
#
# This is the only script CI runs against the real cloud (weekly, through
# Workload Identity Federation with a viewer role on the key project).
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

require_tools
load_config
make_tmp

relay_dir=${1:-}
first_code=0

fail() {
  fail_code=$1
  shift
  log "FAIL [$fail_code]: $*"
  [ "$first_code" -ne 0 ] || first_code=$fail_code
}
ok() { log "ok: $*"; }

# Record
record=$RECORD_DIR/keeper.json
if [ ! -f "$record" ] || [ ! -f "$RECORD_DIR/keeper.pem" ]; then
  die "$EXIT_RECORD" "$RECORD_DIR/keeper.json or keeper.pem missing; run address.sh first"
fi
recorded_address=$(jq -r '.address // empty' "$record")
recorded_version=$(jq -r '.version // empty' "$record")
recorded_sha=$(jq -r '.pemSha256 // empty' "$record")
if [ -z "$recorded_address" ] || [ -z "$recorded_version" ] || [ -z "$recorded_sha" ]; then
  die "$EXIT_RECORD" "$record is missing address, version or pemSha256"
fi
[ "$recorded_version" = "$KEY_VERSION_NAME" ] ||
  die "$EXIT_RECORD" "record is for $recorded_version, config points at $KEY_VERSION_NAME"
[ "$(sha256_file "$RECORD_DIR/keeper.pem")" = "$recorded_sha" ] ||
  die "$EXIT_RECORD" "record/keeper.pem does not match pemSha256 in keeper.json"

# Key attributes
key=$(gcloud kms keys describe "$KEY_NAME" --format=json) ||
  die "$EXIT_KEY_ATTRIBUTES" "cannot describe $KEY_NAME"
purpose=$(printf '%s\n' "$key" | jq -r '.purpose')
algorithm=$(printf '%s\n' "$key" | jq -r '.versionTemplate.algorithm')
protection=$(printf '%s\n' "$key" | jq -r '.versionTemplate.protectionLevel')
window=$(printf '%s\n' "$key" | jq -r '.destroyScheduledDuration // empty')
if [ "$purpose" = "$KEY_PURPOSE_API" ] && [ "$algorithm" = "$KEY_ALGORITHM_API" ] && [ "$protection" = "$KEY_PROTECTION_API" ]; then
  ok "key is $purpose $algorithm $protection"
else
  fail "$EXIT_KEY_ATTRIBUTES" "key is purpose=$purpose algorithm=$algorithm protectionLevel=$protection"
fi
if [ "$window" = "$DESTROY_WINDOW_API" ]; then
  ok "destroy window is $DESTROY_WINDOW"
else
  fail "$EXIT_DESTROY_WINDOW" "destroy window is ${window:-unset}, expected $DESTROY_WINDOW_API"
fi

# Versions: exactly one, and it is version 1, ENABLED.
versions=$(gcloud kms keys versions list --project="$KEY_PROJECT" --location="$LOCATION" \
  --keyring="$KEY_RING" --key="$KEY" --format=json)
count=$(printf '%s\n' "$versions" | jq 'length')
if [ "$count" -eq 1 ]; then
  ok "one key version"
else
  fail "$EXIT_VERSION_COUNT" "$count key versions exist; the address is the property of version 1 alone:$(printf '%s\n' "$versions" | jq -r '.[] | " \(.name | split("/") | last)=\(.state)"' | tr -d '\n')"
fi
state=$(printf '%s\n' "$versions" | jq -r --arg name "$KEY_VERSION_NAME" '.[] | select(.name == $name) | .state')
if [ "$state" = "ENABLED" ]; then
  ok "version 1 is ENABLED"
else
  fail "$EXIT_VERSION_STATE" "version 1 is ${state:-missing}"
fi

# Address
pem=$TMP/live.pem
gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
live_address=$(derive_address "$pem")
if [ "$live_address" = "$recorded_address" ]; then
  ok "live public key derives to $recorded_address"
else
  fail "$EXIT_ADDRESS" "live public key derives to $live_address, record says $recorded_address"
fi
[ "$(sha256_file "$pem")" = "$recorded_sha" ] || fail "$EXIT_ADDRESS" "live PEM differs from record/keeper.pem"

# Key IAM equals the rendered template exactly.
live_policy=$(gcloud kms keys get-iam-policy "$KEY_NAME" --format=json | normalize_policy)
expected_policy=$(render_key_policy | normalize_policy)
if [ "$live_policy" = "$expected_policy" ]; then
  ok "key IAM policy matches policy/key.iam.json.tmpl"
else
  fail "$EXIT_KEY_IAM" "key IAM policy differs from the rendered template"
  printf '%s\n' "$expected_policy" >"$TMP/expected.json"
  printf '%s\n' "$live_policy" >"$TMP/live.json"
  diff -u "$TMP/expected.json" "$TMP/live.json" >&2 || true
fi

# Project audit config still holds the KMS entry.
live_audit=$(gcloud projects get-iam-policy "$KEY_PROJECT" --format=json |
  jq -c --slurpfile audit "$POLICY_DIR/audit.json" \
    '{auditConfigs: ((.auditConfigs // []) | map(select(.service == $audit[0].service)))}' | normalize_policy)
expected_audit=$(jq -c '{auditConfigs: [.]}' "$POLICY_DIR/audit.json" | normalize_policy)
if [ "$live_audit" = "$expected_audit" ]; then
  ok "project audit config has the $KMS_SERVICE entry"
else
  fail "$EXIT_AUDIT" "project audit config lacks the expected $KMS_SERVICE entry"
fi

# Relay repo (optional)
if [ -n "$relay_dir" ]; then
  deploy=$relay_dir/script/Deploy.s.sol
  if [ ! -f "$deploy" ]; then
    fail "$EXIT_RELAY" "$deploy not found"
  else
    relay_keeper=$(grep -E 'KEEPER' "$deploy" | grep -Eo '0x[0-9a-fA-F]{40}' | head -n 1 || true)
    if [ -z "$relay_keeper" ]; then
      fail "$EXIT_RELAY" "no KEEPER address found in $deploy"
    elif [ "$(printf '%s' "$relay_keeper" | tr 'A-F' 'a-f')" = "$(printf '%s' "$recorded_address" | tr 'A-F' 'a-f')" ]; then
      ok "KEEPER in $deploy is $relay_keeper"
    else
      fail "$EXIT_RELAY" "KEEPER in $deploy is $relay_keeper, record says $recorded_address"
    fi
  fi
fi

if [ "$first_code" -eq 0 ]; then
  log "all checks passed"
fi
exit "$first_code"
