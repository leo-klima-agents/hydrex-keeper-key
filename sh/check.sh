#!/bin/sh
# check.sh [RELAY_REPO_DIR]: live state vs record/ and the expected IAM. Read-only.
# Runs every check; exits with the first failure's code (see lib.sh).
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
[ -f "$RECORD_DIR/keeper.pem" ] || die "$EXIT_RECORD" "$RECORD_DIR/keeper.pem missing; run address.sh"
read_record
if [ -z "$recorded_address" ] || [ -z "$recorded_version" ] || [ -z "$recorded_sha" ]; then
  die "$EXIT_RECORD" "record lacks address, version or pemSha256"
fi
[ "$recorded_version" = "$KEY_VERSION_NAME" ] ||
  die "$EXIT_RECORD" "record is for $recorded_version, config is $KEY_VERSION_NAME"
[ "$(sha256_file "$RECORD_DIR/keeper.pem")" = "$recorded_sha" ] ||
  die "$EXIT_RECORD" "keeper.pem does not match pemSha256"

# Key
key=$(find_key)
[ -n "$key" ] || die "$EXIT_KEY_ATTRIBUTES" "$KEY_NAME not found"
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

# Versions: exactly one, version 1, ENABLED, expected algorithm and protection.
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
    fail "$EXIT_VERSION_COUNT" "no key versions"
  else
    fail "$EXIT_VERSION_COUNT" "version 1 missing; present: $listed"
  fi
else
  if [ "$count" -eq 1 ]; then
    ok "one key version, version 1"
  else
    fail "$EXIT_VERSION_COUNT" "$count key versions: $listed"
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

# Address. Only an ENABLED secp256k1 version has a public key to derive from.
if [ "$version_state" = "ENABLED" ] && [ "$version_ok" = yes ]; then
  pem=$TMP/live.pem
  gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
  live_address=$(derive_address "$pem")
  if [ "$live_address" = "$recorded_address" ]; then
    ok "live public key derives to $recorded_address"
    [ "$(sha256_file "$pem")" = "$recorded_sha" ] ||
      log "note: PEM bytes differ from record; run address.sh to refresh"
  else
    fail "$EXIT_ADDRESS" "live public key derives to $live_address, record says $recorded_address"
  fi
else
  log "skipping address check"
fi

# Key IAM
live_policy=$(get_iam "$KEY_NAME" kms keys)
expected_policy=$(render_key_policy)
if policy_differs "$live_policy" "$expected_policy"; then
  fail "$EXIT_KEY_IAM" "key IAM policy differs from template"
  printf '%s\n' "$desired_norm" >"$TMP/expected.json"
  printf '%s\n' "$live_norm" >"$TMP/live.json"
  diff -u "$TMP/expected.json" "$TMP/live.json" >&2 || true
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
  fail "$EXIT_AUDIT" "audit config lacks $KMS_SERVICE entry"
else
  ok "audit config has $KMS_SERVICE entry"
fi

# Org policy
if org_policy_enforced; then
  ok "$SA_KEY_CONSTRAINT enforced"
else
  fail "$EXIT_ORG_POLICY" "$SA_KEY_CONSTRAINT not enforced"
fi

# Relay: script/keeper.json {"address": required, "version": optional}.
if [ -n "$relay_dir" ]; then
  relay_file=$relay_dir/script/keeper.json
  if [ ! -f "$relay_file" ]; then
    fail "$EXIT_RELAY" "$relay_file not found"
  elif ! relay_fields=$(jq -r -s '
      def field: (. // "") | if type != "string" or test("\\p{Cc}") then error("bad field") else . end;
      if length != 1 or (.[0] | type) != "object" then error("not a JSON object")
      else .[0] | (.address | field), (.version | field), "end" end' "$relay_file" 2>/dev/null); then
    fail "$EXIT_RELAY" "$relay_file is not a single JSON object with string fields"
  else
    {
      read -r relay_address
      read -r relay_version
    } <<EOT
$relay_fields
EOT
    relay_lower=$(printf '%s' "$relay_address" | tr 'A-F' 'a-f')
    recorded_lower=$(printf '%s' "$recorded_address" | tr 'A-F' 'a-f')
    if [ -z "$relay_address" ]; then
      fail "$EXIT_RELAY" "$relay_file has no address"
    elif [ "$relay_lower" != "$recorded_lower" ]; then
      fail "$EXIT_RELAY" "KEEPER in $relay_file is $relay_address, record says $recorded_address"
    elif [ -n "$relay_version" ] && [ "$relay_version" != "$recorded_version" ]; then
      fail "$EXIT_RELAY" "$relay_file names $relay_version, record is $recorded_version"
    else
      ok "KEEPER in $relay_file is $recorded_address"
    fi
  fi
fi

[ "$first_code" -ne 0 ] || log "all checks passed"
exit "$first_code"
