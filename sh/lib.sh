#!/bin/sh
# Sourced by every script in sh/. POSIX sh.
# shellcheck disable=SC2034

# Exit codes. 1 is a failed gcloud call.
EXIT_CONFIG=2
EXIT_DEPENDENCY=3
EXIT_KEY_ATTRIBUTES=10
EXIT_DESTROY_WINDOW=11
EXIT_VERSION_STATE=12
EXIT_VERSION_COUNT=13
EXIT_ADDRESS=14
EXIT_KEY_IAM=15
EXIT_AUDIT=16
EXIT_RELAY=17
EXIT_RECORD=18
EXIT_ORG_POLICY=19

MIN_GCLOUD_VERSION=470.0.0
KMS_SERVICE=cloudkms.googleapis.com
KEY_PURPOSE=asymmetric-signing
KEY_PURPOSE_API=ASYMMETRIC_SIGN
KEY_ALGORITHM=ec-sign-secp256k1-sha256
KEY_ALGORITHM_API=EC_SIGN_SECP256K1_SHA256
KEY_PROTECTION=hsm
KEY_PROTECTION_API=HSM
DESTROY_WINDOW=120d          # API maximum; immutable after create
DESTROY_WINDOW_API=10368000s # 120 days in seconds
SA_KEY_CONSTRAINT=iam.disableServiceAccountKeyCreation

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
POLICY_DIR=$REPO_ROOT/policy
CONFIG_FILE=${HYDREX_CONFIG:-$REPO_ROOT/config.env}
RECORD_DIR=${HYDREX_RECORD_DIR:-$REPO_ROOT/record}

log() { printf '%s\n' "$*" >&2; }

die() {
  die_code=$1
  shift
  log "error: $*"
  exit "$die_code"
}

make_tmp() {
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$EXIT_DEPENDENCY" "$1 not found on PATH$2"
}

# version_ge HAVE MIN. First three components only.
version_ge() {
  case "$1$2" in "" | *[!0-9.]*) return 1 ;; esac
  IFS=. read -r have_1 have_2 have_3 have_rest <<EOT
$1
EOT
  IFS=. read -r min_1 min_2 min_3 min_rest <<EOT
$2
EOT
  : "$have_rest" "$min_rest"
  have_1=${have_1:-0} have_2=${have_2:-0} have_3=${have_3:-0}
  min_1=${min_1:-0} min_2=${min_2:-0} min_3=${min_3:-0}
  [ "$have_1" -gt "$min_1" ] && return 0
  [ "$have_1" -lt "$min_1" ] && return 1
  [ "$have_2" -gt "$min_2" ] && return 0
  [ "$have_2" -lt "$min_2" ] && return 1
  [ "$have_3" -ge "$min_3" ]
}

# require_tools [EXTRA...]: gcloud and jq, plus any named extras.
# shellcheck disable=SC2120
require_tools() {
  require_tool gcloud " (https://cloud.google.com/sdk/docs/install)"
  require_tool jq ""
  for extra_tool in "$@"; do
    case "$extra_tool" in
      cast) require_tool cast " (Foundry: https://getfoundry.sh)" ;;
      *) require_tool "$extra_tool" "" ;;
    esac
  done
  gcloud_version_json=$(gcloud version --format=json)
  gcloud_version=$(printf '%s\n' "$gcloud_version_json" | jq -r '."Google Cloud SDK" // ""')
  case "$gcloud_version" in
    "" | *[!0-9.]*) die "$EXIT_DEPENDENCY" "cannot parse gcloud version '$gcloud_version'" ;;
  esac
  version_ge "$gcloud_version" "$MIN_GCLOUD_VERSION" ||
    die "$EXIT_DEPENDENCY" "gcloud $gcloud_version < $MIN_GCLOUD_VERSION"
}

# config.env is authoritative when present; otherwise the environment (CI).
load_config() {
  if [ -n "${HYDREX_CONFIG:-}" ] && [ ! -f "$CONFIG_FILE" ]; then
    die "$EXIT_CONFIG" "HYDREX_CONFIG=$CONFIG_FILE does not exist"
  fi
  if [ -f "$CONFIG_FILE" ]; then
    unset KEY_PROJECT KEEPER_PROJECT LOCATION KEY_RING KEY ADMIN_GROUP KEEPER_SA
    # shellcheck source=/dev/null
    . "$CONFIG_FILE"
  fi
  LOCATION=${LOCATION:-us}
  KEY_RING=${KEY_RING:-hydrex-keeper}
  KEY=${KEY:-keeper}
  KEEPER_SA=${KEEPER_SA:-}

  for required in KEY_PROJECT KEEPER_PROJECT ADMIN_GROUP; do
    eval "value=\${$required:-}"
    [ -n "$value" ] || die "$EXIT_CONFIG" "$required is not set (see config.env.example)"
  done
  [ "$KEY_PROJECT" != "$KEEPER_PROJECT" ] ||
    die "$EXIT_CONFIG" "KEY_PROJECT and KEEPER_PROJECT must differ"
  case "$ADMIN_GROUP" in
    *@*) ;;
    *) die "$EXIT_CONFIG" "ADMIN_GROUP must be an email address" ;;
  esac
  if [ -n "$KEEPER_SA" ]; then
    case "$KEEPER_SA" in
      *"@$KEEPER_PROJECT.iam.gserviceaccount.com") ;;
      *) die "$EXIT_CONFIG" "KEEPER_SA must be a service account in $KEEPER_PROJECT" ;;
    esac
  fi

  KEY_RING_NAME=projects/$KEY_PROJECT/locations/$LOCATION/keyRings/$KEY_RING
  KEY_NAME=$KEY_RING_NAME/cryptoKeys/$KEY
  KEY_VERSION_NAME=$KEY_NAME/cryptoKeyVersions/1
}

# Renders policy/key.iam.json.tmpl. Bindings with an empty principal are dropped.
render_key_policy() {
  jq --arg admin "$ADMIN_GROUP" --arg keeper "$KEEPER_SA" '
    walk(if type == "string"
         then (split("${ADMIN_GROUP}") | join($admin)) | (split("${KEEPER_SA}") | join($keeper))
         else . end)
    | .bindings |= map(.members |= map(select(endswith(":") | not)) | select(.members | length > 0))
  ' "$POLICY_DIR/key.iam.json.tmpl"
}

# Field readers: one jq call, one field per line, "end" so the last read never hits EOF.
# Called inside conditions, so a jq failure dies explicitly.

# Sets purpose, algorithm, protection, window. True if the first three are expected.
read_key_attributes() {
  key_fields=$(printf '%s\n' "$1" | jq -r '
    (.purpose // ""), (.versionTemplate.algorithm // ""),
    (.versionTemplate.protectionLevel // ""), (.destroyScheduledDuration // ""), "end"') ||
    die 1 "cannot parse cryptoKey JSON"
  {
    read -r purpose
    read -r algorithm
    read -r protection
    read -r window
  } <<EOT
$key_fields
EOT
  [ "$purpose" = "$KEY_PURPOSE_API" ] &&
    [ "$algorithm" = "$KEY_ALGORITHM_API" ] &&
    [ "$protection" = "$KEY_PROTECTION_API" ]
}

# Sets version_state, version_algorithm, version_protection. True if the last two are expected.
read_version_attributes() {
  version_fields=$(printf '%s\n' "$1" | jq -r '
    (.state // ""), (.algorithm // ""), (.protectionLevel // ""), "end"') ||
    die 1 "cannot parse cryptoKeyVersion JSON"
  {
    read -r version_state
    read -r version_algorithm
    read -r version_protection
  } <<EOT
$version_fields
EOT
  [ "$version_algorithm" = "$KEY_ALGORITHM_API" ] &&
    [ "$version_protection" = "$KEY_PROTECTION_API" ]
}

# Sets recorded_version, recorded_address, recorded_sha from record/keeper.json.
# Dies 18 unless the file is one JSON object with single-line string fields.
read_record() {
  record_file=$RECORD_DIR/keeper.json
  [ -f "$record_file" ] || die "$EXIT_RECORD" "$record_file missing; run address.sh"
  record_fields=$(jq -r -s '
    def field: (. // "") | if type != "string" or test("\\p{Cc}") then error("bad field") else . end;
    if length != 1 then error("not exactly one JSON document")
    elif (.[0] | type) != "object" then error("not a JSON object")
    else .[0] | (.version | field), (.address | field), (.pemSha256 | field), "end" end' \
    "$record_file" 2>/dev/null) ||
    die "$EXIT_RECORD" "$record_file is not a single JSON object with string fields"
  {
    read -r recorded_version
    read -r recorded_address
    read -r recorded_sha
  } <<EOT
$record_fields
EOT
}

# Filtered lists: absence is an empty result, not an error to parse.
find_keyring() {
  find_keyring_list=$(gcloud kms keyrings list --project="$KEY_PROJECT" --location="$LOCATION" \
    --filter="name=$KEY_RING_NAME" --format=json)
  printf '%s\n' "$find_keyring_list" | jq -r --arg name "$KEY_RING_NAME" '.[] | select(.name == $name) | .name'
}

find_key() {
  find_key_list=$(gcloud kms keys list --project="$KEY_PROJECT" --location="$LOCATION" --keyring="$KEY_RING" \
    --filter="name=$KEY_NAME" --format=json)
  printf '%s\n' "$find_key_list" | jq -c --arg name "$KEY_NAME" '.[] | select(.name == $name)'
}

org_policy_enforced() {
  org_policy_json=$(gcloud resource-manager org-policies describe "$SA_KEY_CONSTRAINT" \
    --project="$KEY_PROJECT" --effective --format=json)
  [ "$(printf '%s\n' "$org_policy_json" | jq -r '.booleanPolicy.enforced // false')" = "true" ]
}

describe_version_1() {
  version_json=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json)
  read_version_attributes "$version_json" ||
    die "$EXIT_KEY_ATTRIBUTES" "version 1 is algorithm=$version_algorithm protectionLevel=$version_protection"
}

# Canonical policy: sorted bindings and audit configs, no etag or version. stdin -> stdout.
normalize_policy() {
  jq -S '{
    bindings: ((.bindings // [])
      | map({role, members: ((.members // []) | sort)} + (if .condition then {condition} else {} end))
      | sort_by([.role, ((.condition // {}) | tojson)])),
    auditConfigs: ((.auditConfigs // [])
      | map({service, auditLogConfigs: ((.auditLogConfigs // [])
          | map({logType} + (if .exemptedMembers then {exemptedMembers: (.exemptedMembers | sort)} else {} end))
          | sort_by(.logType))})
      | sort_by(.service))
  }'
}

# policy_differs LIVE DESIRED. Leaves live_norm and desired_norm set.
policy_differs() {
  live_norm=$(printf '%s\n' "$1" | normalize_policy)
  desired_norm=$(printf '%s\n' "$2" | normalize_policy)
  [ "$live_norm" != "$desired_norm" ]
}

# get_iam RESOURCE gcloud-subcommand...
get_iam() {
  iam_resource=$1
  shift
  gcloud "$@" get-iam-policy "$iam_resource" --format=json
}

# write_iam_if_changed RESOURCE LIVE DESIRED gcloud-subcommand...
# Writes DESIRED in full with LIVE's etag. Never merges.
write_iam_if_changed() {
  iam_resource=$1
  iam_live=$2
  iam_desired=$3
  shift 3
  if ! policy_differs "$iam_live" "$iam_desired"; then
    log "iam: $iam_resource unchanged"
    return 0
  fi
  iam_etag=$(printf '%s\n' "$iam_live" | jq -r '.etag // empty')
  iam_file=$TMP/policy.json
  printf '%s\n' "$iam_desired" | jq --arg etag "$iam_etag" '.etag = $etag' >"$iam_file"
  log "iam: writing $iam_resource"
  gcloud "$@" set-iam-policy "$iam_resource" "$iam_file" >/dev/null
}

# set_iam_authoritative RESOURCE DESIRED gcloud-subcommand...
set_iam_authoritative() {
  set_iam_resource=$1
  set_iam_desired=$2
  shift 2
  set_iam_live=$(get_iam "$set_iam_resource" "$@")
  write_iam_if_changed "$set_iam_resource" "$set_iam_live" "$set_iam_desired" "$@"
}

# derive_address PEM: PEM -> DER -> last 64 bytes (X||Y) -> keccak256 -> last 20 bytes -> EIP-55.
SECP256K1_SPKI_PREFIX=3056301006072a8648ce3d020106052b8104000a03420004

derive_address() {
  derive_der=$TMP/pub.der
  openssl pkey -pubin -in "$1" -outform DER -out "$derive_der"
  derive_hex=$(od -An -v -tx1 "$derive_der" | tr -d ' \n')
  case "$derive_hex" in
    "$SECP256K1_SPKI_PREFIX"*) ;;
    *) die "$EXIT_KEY_ATTRIBUTES" "not an uncompressed secp256k1 SPKI" ;;
  esac
  [ ${#derive_hex} -eq 176 ] || die "$EXIT_KEY_ATTRIBUTES" "unexpected DER length"
  derive_xy=$(tail -c 64 "$derive_der" | od -An -v -tx1 | tr -d ' \n')
  derive_hash=$(cast keccak "0x$derive_xy")
  derive_lower=0x$(printf '%s' "$derive_hash" | tail -c 40)
  cast to-check-sum-address "$derive_lower"
}

sha256_file() {
  openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}
