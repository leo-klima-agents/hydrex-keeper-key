#!/bin/sh
# check.sh: live state vs record/ and the expected IAM. Read-only.
# Runs every check; exits 1 if any failed.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

[ $# -eq 0 ] || die "usage: $0"
require_tools openssl cast
load_config
make_tmp

failed=0
fail() {
  log "FAIL: $*"
  failed=1
}
ok() { log "ok: $*"; }

# Record problems are reported; only the address comparison is skipped.
record_ok=yes
read_record
if [ -z "$recorded_address" ] || [ -z "$recorded_version" ] || [ -z "$recorded_sha" ]; then
  fail "record lacks address, version or pemSha256"
  record_ok=no
elif [ "$recorded_version" != "$KEY_VERSION_NAME" ]; then
  fail "record is for $recorded_version, config is $KEY_VERSION_NAME"
  record_ok=no
elif [ ! -f "$RECORD_DIR/keeper.pem" ]; then
  fail "$RECORD_DIR/keeper.pem missing; run address.sh"
  record_ok=no
elif [ "$(sha256_file "$RECORD_DIR/keeper.pem")" != "$recorded_sha" ]; then
  fail "keeper.pem does not match pemSha256"
  record_ok=no
else
  ok "record is consistent"
fi

# Key
key=$(find_key)
[ -n "$key" ] || die "$KEY_NAME not found"
if read_key_attrs "$key"; then
  ok "key is $purpose $algorithm $protection"
else
  fail "key is purpose=$purpose algorithm=$algorithm protectionLevel=$protection"
fi
if [ "$window" = "$DESTROY_WINDOW_API" ]; then
  ok "destroy window is $DESTROY_WINDOW"
else
  fail "destroy window is ${window:-unset}, expected $DESTROY_WINDOW_API"
fi

# Versions: exactly one, version 1, ENABLED, expected algorithm and protection.
versions=$(gcloud kms keys versions list --project="$KEY_PROJECT" --location="$LOCATION" \
  --keyring="$KEY_RING" --key="$KEY" --format=json)
count=$(printf '%s\n' "$versions" | jq 'length')
listed=$(printf '%s\n' "$versions" | jq -r '[.[] | "\(.name | split("/") | last)=\(.state)"] | join(" ")')
version1=$(printf '%s\n' "$versions" | jq -c --arg name "$KEY_VERSION_NAME" '.[] | select(.name == $name)')
version_state=missing version_ok=no
if [ -z "$version1" ]; then
  fail "version 1 missing; present: ${listed:-none}"
else
  if [ "$count" -eq 1 ]; then
    ok "one key version, version 1"
  else
    fail "$count key versions: $listed"
  fi
  if read_version_attrs "$version1"; then
    ok "version 1 is $version_algorithm $version_protection"
    version_ok=yes
  else
    fail "version 1 is algorithm=$version_algorithm protectionLevel=$version_protection"
  fi
  if [ "$version_state" = "ENABLED" ]; then
    ok "version 1 is ENABLED"
  else
    fail "version 1 is $version_state"
  fi
fi

# Address
if [ "$record_ok" = yes ] && [ "$version_state" = "ENABLED" ] && [ "$version_ok" = yes ]; then
  pem=$TMP/live.pem
  gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
  live_address=$(derive_address "$pem")
  if [ "$live_address" = "$recorded_address" ]; then
    ok "live public key derives to $recorded_address"
    [ "$(sha256_file "$pem")" = "$recorded_sha" ] || log "note: PEM bytes differ from record; run address.sh to refresh"
  else
    fail "live public key derives to $live_address, record says $recorded_address"
  fi
else
  log "skipping address check"
fi

# Key IAM
live_policy=$(get_iam "$KEY_NAME" kms keys)
expected_policy=$(render_key_policy)
if policy_differs "$live_policy" "$expected_policy"; then
  fail "key IAM policy differs from template"
  show_policy_diff
else
  ok "key IAM policy matches template"
fi

# Audit config
project_policy=$(get_iam "$KEY_PROJECT" projects)
live_audit=$(printf '%s\n' "$project_policy" |
  jq -c --slurpfile audit "$POLICY_DIR/audit.json" \
    '{auditConfigs: ((.auditConfigs // []) | map(select(.service == $audit[0].service)))}')
expected_audit=$(jq -c '{auditConfigs: [.]}' "$POLICY_DIR/audit.json")
if policy_differs "$live_audit" "$expected_audit"; then
  fail "audit config for $KMS_SERVICE differs from policy/audit.json"
  show_policy_diff
else
  ok "audit config for $KMS_SERVICE matches policy/audit.json"
fi

# Org policy. A failed read is a gcloud failure, not drift.
org_policy_enforced && org_status=0 || org_status=$?
case "$org_status" in
  0) ok "$SA_KEY_CONSTRAINT enforced" ;;
  2) die "cannot read $SA_KEY_CONSTRAINT" ;;
  *) fail "$SA_KEY_CONSTRAINT not enforced" ;;
esac

[ "$failed" -ne 0 ] || log "all checks passed"
exit "$failed"
