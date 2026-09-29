#!/bin/sh
# Sourced by the scripts in sh/.
# shellcheck disable=SC2034

# cloudresourcemanager: the project IAM policy, which carries the audit config.
# iam, iamcredentials, sts: the CI service account and its Workload Identity Federation.
SERVICES="cloudkms.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com iamcredentials.googleapis.com
sts.googleapis.com"
KMS_SERVICE=cloudkms.googleapis.com
KEY_PURPOSE=asymmetric-signing
KEY_PURPOSE_API=ASYMMETRIC_SIGN
KEY_ALGORITHM=ec-sign-secp256k1-sha256
KEY_ALGORITHM_API=EC_SIGN_SECP256K1_SHA256
KEY_PROTECTION=hsm
KEY_PROTECTION_API=HSM
DESTROY_WINDOW=120d          # the longest KMS allows; fixed at creation
DESTROY_WINDOW_API=10368000s # 120 days, as the API reports it

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
POLICY_DIR=$REPO_ROOT/policy
CONFIG_FILE=${HYDREX_CONFIG:-$REPO_ROOT/config.env}
RECORD_DIR=${HYDREX_RECORD_DIR:-$REPO_ROOT/record}

log() { printf '%s\n' "$*" >&2; }

die() {
  log "error: $*"
  exit 1
}

make_tmp() {
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# require_tools TOOL...: dies unless every TOOL is on PATH.
require_tools() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
  done
}

load_config() {
  [ -f "$CONFIG_FILE" ] || die "$CONFIG_FILE missing; copy config.env.example"
  case "$CONFIG_FILE" in */*) ;; *) CONFIG_FILE=./$CONFIG_FILE ;; esac # else `.` searches PATH
  unset KEY_PROJECT KEEPER_PROJECT LOCATION KEY_RING KEY ADMIN_MEMBER KEEPER_SA
  # shellcheck source=/dev/null
  . "$CONFIG_FILE"
  LOCATION=${LOCATION:-us}
  KEY_RING=${KEY_RING:-hydrex-keeper}
  KEY=${KEY:-hydrex-keeper-v1}
  KEEPER_SA=${KEEPER_SA:-}

  for required in KEY_PROJECT KEEPER_PROJECT ADMIN_MEMBER; do
    eval "value=\${$required:-}"
    [ -n "$value" ] || die "$required is not set in $CONFIG_FILE"
  done
  [ "$KEY_PROJECT" != "$KEEPER_PROJECT" ] ||
    die "KEY_PROJECT and KEEPER_PROJECT must differ"
  case "$ADMIN_MEMBER" in
    user:?*@?* | group:?*@?*) ;;
    *) die "ADMIN_MEMBER must be user:EMAIL or group:EMAIL" ;;
  esac
  if [ -n "$KEEPER_SA" ]; then
    case "$KEEPER_SA" in
      *"@$KEEPER_PROJECT.iam.gserviceaccount.com") ;;
      *) die "KEEPER_SA must be a service account in $KEEPER_PROJECT" ;;
    esac
  fi

  KEY_RING_NAME=projects/$KEY_PROJECT/locations/$LOCATION/keyRings/$KEY_RING
  KEY_NAME=$KEY_RING_NAME/cryptoKeys/$KEY
  KEY_VERSION_NAME=$KEY_NAME/cryptoKeyVersions/1
}

# render_policy FILE: policy/FILE with the principals filled in. A binding whose principal is empty is dropped.
render_policy() {
  jq --arg admin "$ADMIN_MEMBER" --arg keeper "$KEEPER_SA" '
    walk(if type == "string"
         then (split("${ADMIN_MEMBER}") | join($admin)) | (split("${KEEPER_SA}") | join($keeper))
         else . end)
    | .bindings |= map(.members |= map(select(endswith(":") | not)) | select(.members | length > 0))
  ' "$POLICY_DIR/$1"
}

# json_field JSON FILTER: "" if null or absent.
json_field() {
  printf '%s\n' "$1" | jq -r "($2) // \"\"" || die "cannot parse JSON"
}

# require_json JSON LABEL: dies unless JSON parses.
require_json() {
  printf '%s\n' "$1" | jq -e . >/dev/null 2>&1 || die "$2 is not JSON: $1"
}

# Canonical policy: sorted bindings, without etag and version.
normalize_policy() {
  jq -S '{
    bindings: ((.bindings // [])
      | map({role, members: ((.members // []) | sort)} + (if .condition then {condition} else {} end))
      | sort_by([.role, ((.condition // {}) | tojson)]))
  }'
}

# policy_differs LIVE DESIRED. Leaves live_norm and desired_norm set.
policy_differs() {
  live_norm=$(printf '%s\n' "$1" | normalize_policy)
  desired_norm=$(printf '%s\n' "$2" | normalize_policy)
  [ "$live_norm" != "$desired_norm" ]
}

# Prints the diff from the last policy_differs.
show_policy_diff() {
  printf '%s\n' "$desired_norm" >"$TMP/expected.json"
  printf '%s\n' "$live_norm" >"$TMP/live.json"
  diff -u "$TMP/expected.json" "$TMP/live.json" | tail -n +3 >&2 || true
}

# get_iam RESOURCE FLAGS gcloud-subcommand...: FLAGS is one word-split string, "" for none.
get_iam() {
  iam_resource=$1
  iam_flags=$2
  shift 2
  # shellcheck disable=SC2086
  iam_json=$(gcloud "$@" get-iam-policy $iam_flags "$iam_resource" --format=json) || die "cannot read IAM policy of $iam_resource"
  require_json "$iam_json" "IAM policy of $iam_resource"
  printf '%s\n' "$iam_json"
}

# set_iam RESOURCE FLAGS DESIRED gcloud-subcommand...: writes DESIRED in full, with the live etag, unless it matches.
set_iam() {
  set_iam_resource=$1
  set_iam_flags=$2
  set_iam_desired=$3
  shift 3
  set_iam_live=$(get_iam "$set_iam_resource" "$set_iam_flags" "$@")
  if ! policy_differs "$set_iam_live" "$set_iam_desired"; then
    log "iam: $set_iam_resource unchanged"
    return 0
  fi
  set_iam_etag=$(printf '%s\n' "$set_iam_live" | jq -r '.etag // empty')
  printf '%s\n' "$set_iam_desired" | jq --arg etag "$set_iam_etag" '.etag = $etag' >"$TMP/policy.json"
  log "iam: writing $set_iam_resource"
  # shellcheck disable=SC2086
  gcloud "$@" set-iam-policy $set_iam_flags "$set_iam_resource" "$TMP/policy.json" >/dev/null
}

# Canonical audit configs: sorted, with sorted log types and exempted members.
normalize_audit() {
  jq -S '{
    auditConfigs: ((.auditConfigs // [])
      | map({service, auditLogConfigs: ((.auditLogConfigs // [])
          | map({logType} + (if .exemptedMembers then {exemptedMembers: (.exemptedMembers | sort)} else {} end))
          | sort_by(.logType))})
      | sort_by(.service))
  }'
}

# audit_differs LIVE: whether the KMS entry of project policy LIVE's audit configs differs from policy/audit.json.
# Leaves live_norm and desired_norm set.
audit_differs() {
  live_norm=$(printf '%s\n' "$1" | jq --slurpfile audit "$POLICY_DIR/audit.json" \
    '{auditConfigs: [.auditConfigs[]? | select(.service == $audit[0].service)]}' | normalize_audit)
  desired_norm=$(jq '{auditConfigs: [.]}' "$POLICY_DIR/audit.json" | normalize_audit)
  [ "$live_norm" != "$desired_norm" ]
}

# set_audit: writes policy/audit.json as the KMS audit config of KEY_PROJECT unless it matches. The rest of the
# project policy, and its etag, are written back as read.
set_audit() {
  set_audit_live=$(get_iam "$KEY_PROJECT" "" projects)
  if ! audit_differs "$set_audit_live"; then
    log "audit: $KEY_PROJECT unchanged"
    return 0
  fi
  printf '%s\n' "$set_audit_live" | jq --slurpfile audit "$POLICY_DIR/audit.json" \
    '.auditConfigs = ((.auditConfigs // []) | map(select(.service != $audit[0].service))) + $audit' >"$TMP/policy.json"
  log "audit: writing $KEY_PROJECT"
  gcloud projects set-iam-policy "$KEY_PROJECT" "$TMP/policy.json" >/dev/null
}

# read_key_attrs KEY: sets purpose, algorithm, protection and window from the key's JSON.
read_key_attrs() {
  purpose=$(json_field "$1" .purpose)
  algorithm=$(json_field "$1" .versionTemplate.algorithm)
  protection=$(json_field "$1" .versionTemplate.protectionLevel)
  window=$(json_field "$1" .destroyScheduledDuration)
}

# read_version_attrs VERSION: sets version_state, version_algorithm and version_protection from the version's JSON.
read_version_attrs() {
  version_state=$(json_field "$1" .state)
  version_algorithm=$(json_field "$1" .algorithm)
  version_protection=$(json_field "$1" .protectionLevel)
}

# read_record: sets recorded_version and recorded_address from record/keeper.json.
read_record() {
  record_file=$RECORD_DIR/keeper.json
  [ -f "$record_file" ] || die "$record_file missing; run address.sh"
  record_json=$(jq -ce 'select(type == "object")' "$record_file" 2>/dev/null) || die "$record_file is not a JSON object"
  recorded_version=$(json_field "$record_json" .version)
  recorded_address=$(json_field "$record_json" .address)
}

# A listing tells an absent key ring or key from a failed call, which describe would not.
# find_keyring: KEY_RING_NAME if the key ring exists, else "".
find_keyring() {
  rings=$(gcloud kms keyrings list --project="$KEY_PROJECT" --location="$LOCATION" --format=json) || die "cannot list key rings"
  require_json "$rings" "key ring list"
  printf '%s\n' "$rings" | jq -r --arg name "$KEY_RING_NAME" 'first(.[] | select(.name == $name) | .name) // ""'
}

# find_key: the key as JSON, or "".
find_key() {
  keys=$(gcloud kms keys list --project="$KEY_PROJECT" --location="$LOCATION" --keyring="$KEY_RING" --format=json) ||
    die "cannot list keys of $KEY_RING_NAME"
  require_json "$keys" "key list"
  printf '%s\n' "$keys" | jq -c --arg name "$KEY_NAME" 'first(.[] | select(.name == $name)) // empty'
}

# describe_version_1: read_version_attrs on the live version 1, which must be of the expected kind.
describe_version_1() {
  version_json=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json) || die "cannot describe $KEY_VERSION_NAME"
  require_json "$version_json" "key version 1"
  read_version_attrs "$version_json"
  if [ "$version_algorithm" != "$KEY_ALGORITHM_API" ] || [ "$version_protection" != "$KEY_PROTECTION_API" ]; then
    die "version 1 is algorithm=$version_algorithm protectionLevel=$version_protection"
  fi
}

require_keccak() {
  printf '' | openssl dgst -KECCAK-256 >/dev/null 2>&1 ||
    die "$(openssl version) has no KECCAK-256; needs OpenSSL 3.2 or newer"
}

keccak256_hex() {
  openssl dgst -KECCAK-256 -binary | od -An -v -tx1 | tr -d ' \n'
}

# derive_address PEM: the Ethereum address of the secp256k1 public key in PEM: the last 20 bytes of the Keccak-256 of
# its X and Y coordinates, in EIP-55 mixed case.
SECP256K1_SPKI_PREFIX=3056301006072a8648ce3d020106052b8104000a03420004

derive_address() {
  derive_der=$TMP/pub.der
  openssl pkey -pubin -in "$1" -outform DER -out "$derive_der"
  derive_hex=$(od -An -v -tx1 "$derive_der" | tr -d ' \n')
  case "$derive_hex" in
    "$SECP256K1_SPKI_PREFIX"*) ;;
    *) die "not an uncompressed secp256k1 SPKI" ;;
  esac
  [ ${#derive_hex} -eq 176 ] || die "unexpected DER length"
  derive_lower=$(tail -c 64 "$derive_der" | keccak256_hex | tail -c 40)
  derive_mask=$(printf '%s' "$derive_lower" | keccak256_hex)
  if [ ${#derive_lower} -ne 40 ] || [ ${#derive_mask} -ne 64 ]; then die "Keccak-256 failed"; fi
  awk -v a="$derive_lower" -v h="$derive_mask" 'BEGIN {
    printf "0x"
    for (i = 1; i <= 40; i++) { c = substr(a, i, 1); printf "%s", (c ~ /[a-f]/ && index("89abcdef", substr(h, i, 1))) ? toupper(c) : c }
    printf "\n" }'
}
