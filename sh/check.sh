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

[ $# -le 1 ] || die "$EXIT_CONFIG" "usage: $0 [RELAY_REPO_DIR]"
require_tools openssl cast
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
[ -f "$RECORD_DIR/keeper.pem" ] || die "$EXIT_RECORD" "$RECORD_DIR/keeper.pem missing; run address.sh first"
read_record
if [ -z "$recorded_address" ] || [ -z "$recorded_version" ] || [ -z "$recorded_sha" ]; then
  die "$EXIT_RECORD" "$RECORD_DIR/keeper.json is missing address, version or pemSha256"
fi
[ "$recorded_version" = "$KEY_VERSION_NAME" ] ||
  die "$EXIT_RECORD" "record is for $recorded_version, config points at $KEY_VERSION_NAME"
[ "$(sha256_file "$RECORD_DIR/keeper.pem")" = "$recorded_sha" ] ||
  die "$EXIT_RECORD" "record/keeper.pem does not match pemSha256 in keeper.json"

# Key attributes. Absence is a structured empty lookup, exit 10; any other
# failure is gcloud's, exit 1 with its message.
key=$(find_key)
[ -n "$key" ] || die "$EXIT_KEY_ATTRIBUTES" "key $KEY_NAME not found"
if read_key_attributes "$key"; then
  ok "key is $purpose $algorithm $protection"
else
  fail "$EXIT_KEY_ATTRIBUTES" "key is purpose=$purpose algorithm=$algorithm protectionLevel=$protection"
fi
if [ "$window" = "$DESTROY_WINDOW_API" ]; then
  ok "destroy window is $DESTROY_WINDOW"
else
  fail "$EXIT_DESTROY_WINDOW" "destroy window is ${window:-unset}, expected $DESTROY_WINDOW_API"
fi

# Versions: exactly one, and it is version 1, ENABLED, with the expected
# algorithm and protection level of its own. One jq pass over the list; one
# failure per distinct fact.
versions=$(gcloud kms keys versions list --project="$KEY_PROJECT" --location="$LOCATION" \
  --keyring="$KEY_RING" --key="$KEY" --format=json)
version_fields=$(printf '%s\n' "$versions" | jq -r --arg name "$KEY_VERSION_NAME" '
  length,
  ([.[] | "\(.name | split("/") | last)=\(.state)"] | join(" ")),
  ((map(select(.name == $name)) | first) // "" | if . == "" then "" else tojson end),
  "end"')
{
  read -r count
  read -r listed
  read -r version1
} <<EOT
$version_fields
EOT
version_state=missing version_ok=no
if [ -z "$version1" ]; then
  if [ "$count" -eq 0 ]; then
    fail "$EXIT_VERSION_COUNT" "no key versions exist"
  else
    fail "$EXIT_VERSION_COUNT" "version 1 is missing; versions present: $listed"
  fi
else
  if [ "$count" -eq 1 ]; then
    ok "one key version, and it is version 1"
  else
    fail "$EXIT_VERSION_COUNT" "$count key versions exist; the address is the property of version 1 alone: $listed"
  fi
  if read_version_attributes "$version1"; then
    ok "version 1 is $version_algorithm $version_protection"
    version_ok=yes
  else
    fail "$EXIT_KEY_ATTRIBUTES" "version 1 is algorithm=${version_algorithm:-?} protectionLevel=${version_protection:-?}"
  fi
  if [ "$version_state" = "ENABLED" ]; then
    ok "version 1 is ENABLED"
  else
    fail "$EXIT_VERSION_STATE" "version 1 is ${version_state:-unknown}"
  fi
fi

# Address. Only an ENABLED secp256k1 version has a public key this derivation
# applies to; for anything else the failures above already say what is wrong
# and the remaining checks still run. For such a version a failed fetch is a
# gcloud failure, exit 1.
if [ "$version_state" = "ENABLED" ] && [ "$version_ok" = yes ]; then
  pem=$TMP/live.pem
  gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
  live_address=$(derive_address "$pem")
  if [ "$live_address" = "$recorded_address" ]; then
    ok "live public key derives to $recorded_address"
    # Same key, different PEM bytes can only be a formatting change in
    # gcloud's output. Worth a note, not a failure; address.sh refreshes it.
    [ "$(sha256_file "$pem")" = "$recorded_sha" ] ||
      log "note: live PEM bytes differ from record/keeper.pem while the address matches; run address.sh to refresh the record"
  else
    fail "$EXIT_ADDRESS" "live public key derives to $live_address, record says $recorded_address"
  fi
else
  log "skipping address check: version 1 is not an ENABLED $KEY_ALGORITHM_API $KEY_PROTECTION_API version"
fi

# Key IAM equals the rendered template exactly. Reads are assigned before they
# are compared so a failed gcloud call aborts instead of reading as drift.
live_policy=$(get_iam "$KEY_NAME" kms keys)
expected_policy=$(render_key_policy)
if policy_differs "$live_policy" "$expected_policy"; then
  fail "$EXIT_KEY_IAM" "key IAM policy differs from the rendered template"
  printf '%s\n' "$desired_norm" >"$TMP/expected.json"
  printf '%s\n' "$live_norm" >"$TMP/live.json"
  diff -u "$TMP/expected.json" "$TMP/live.json" >&2 || true
else
  ok "key IAM policy matches policy/key.iam.json.tmpl"
fi

# Project audit config still holds the KMS entry.
project_policy=$(get_iam "$KEY_PROJECT" projects)
live_audit=$(printf '%s\n' "$project_policy" |
  jq -c --slurpfile audit "$POLICY_DIR/audit.json" \
    '{auditConfigs: ((.auditConfigs // []) | map(select(.service == $audit[0].service)))}')
expected_audit=$(jq -c '{auditConfigs: [.]}' "$POLICY_DIR/audit.json")
if policy_differs "$live_audit" "$expected_audit"; then
  fail "$EXIT_AUDIT" "project audit config lacks the expected $KMS_SERVICE entry"
else
  ok "project audit config has the $KMS_SERVICE entry"
fi

# Relay repo (optional)
if [ -n "$relay_dir" ]; then
  deploy=$relay_dir/script/Deploy.s.sol
  if [ ! -f "$deploy" ]; then
    fail "$EXIT_RELAY" "$deploy not found"
  else
    # The KEEPER assignment itself, in the source with comments and string
    # literals removed and lines joined: not a commented-out old value, not a
    # KEEPER_* identifier, not a `KEEPER ==` comparison, and wrapped
    # assignments still match. The literal may be wrapped in any number of
    # address(...) or payable(...) casts. `$` is an identifier character in
    # Solidity, so `$KEEPER` is not KEEPER. Exactly one distinct address is
    # required.
    relay_addresses=$(strip_solidity_comments <"$deploy" |
      grep -Eo '(^|[^A-Za-z0-9_$])KEEPER[[:space:]]*=[[:space:]]*((address|payable)\([[:space:]]*)*0x[0-9a-fA-F]{40}' |
      grep -Eo '0x[0-9a-fA-F]{40}' | tr 'A-F' 'a-f' | sort -u)
    relay_count=$(printf '%s' "$relay_addresses" | grep -c . || true)
    relay_keeper=$(printf '%s' "$relay_addresses" | head -n 1)
    if [ "$relay_count" -eq 0 ]; then
      fail "$EXIT_RELAY" "no KEEPER assignment found in $deploy"
    elif [ "$relay_count" -gt 1 ]; then
      fail "$EXIT_RELAY" "$relay_count different KEEPER assignments in $deploy:$(printf '%s' "$relay_addresses" | tr '\n' ' ' | sed 's/^/ /')"
    elif [ "$relay_keeper" = "$(printf '%s' "$recorded_address" | tr 'A-F' 'a-f')" ]; then
      ok "KEEPER in $deploy is $recorded_address"
    else
      fail "$EXIT_RELAY" "KEEPER in $deploy is $relay_keeper, record says $recorded_address"
    fi
  fi
fi

if [ "$first_code" -eq 0 ]; then
  log "all checks passed"
fi
exit "$first_code"
