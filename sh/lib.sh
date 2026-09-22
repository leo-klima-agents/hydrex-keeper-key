#!/bin/sh
# Sourced by every script in sh/. POSIX sh.
# shellcheck disable=SC2034

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
  log "error: $*"
  exit 1
}

make_tmp() {
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# version_ge HAVE MIN: numeric compare of the first three dotted components.
version_ge() {
  printf '%s %s\n' "$1" "$2" | awk '{
    split($1, a, "."); split($2, b, ".")
    for (i = 1; i <= 3; i++) { if (a[i] + 0 > b[i] + 0) exit 0; if (a[i] + 0 < b[i] + 0) exit 1 }
    exit 0 }'
}

# require_tools [EXTRA...]: gcloud and jq, plus any named extras.
# shellcheck disable=SC2120
require_tools() {
  for tool in gcloud jq "$@"; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
  done
  gcloud_version_json=$(gcloud version --format=json)
  gcloud_version=$(printf '%s\n' "$gcloud_version_json" | jq -r '."Google Cloud SDK" // ""')
  case "$gcloud_version" in
    "" | *[!0-9.]*) die "cannot parse gcloud version '$gcloud_version'" ;;
  esac
  version_ge "$gcloud_version" "$MIN_GCLOUD_VERSION" || die "gcloud $gcloud_version < $MIN_GCLOUD_VERSION"
}

load_config() {
  [ -f "$CONFIG_FILE" ] || die "$CONFIG_FILE missing; copy config.env.example"
  case "$CONFIG_FILE" in */*) ;; *) CONFIG_FILE=./$CONFIG_FILE ;; esac # `.` searches PATH otherwise
  unset KEY_PROJECT KEEPER_PROJECT LOCATION KEY_RING KEY ADMIN_GROUP KEEPER_SA
  # shellcheck source=/dev/null
  . "$CONFIG_FILE"
  LOCATION=${LOCATION:-us}
  KEY_RING=${KEY_RING:-hydrex-keeper}
  KEY=${KEY:-keeper}
  KEEPER_SA=${KEEPER_SA:-}

  for required in KEY_PROJECT KEEPER_PROJECT ADMIN_GROUP; do
    eval "value=\${$required:-}"
    [ -n "$value" ] || die "$required is not set in $CONFIG_FILE"
  done
  [ "$KEY_PROJECT" != "$KEEPER_PROJECT" ] ||
    die "KEY_PROJECT and KEEPER_PROJECT must differ"
  case "$ADMIN_GROUP" in
    *@*) ;;
    *) die "ADMIN_GROUP must be an email address" ;;
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

# Renders policy/key.iam.json.tmpl. Bindings with an empty principal are dropped.
render_key_policy() {
  jq --arg admin "$ADMIN_GROUP" --arg keeper "$KEEPER_SA" '
    walk(if type == "string"
         then (split("${ADMIN_GROUP}") | join($admin)) | (split("${KEEPER_SA}") | join($keeper))
         else . end)
    | .bindings |= map(.members |= map(select(endswith(":") | not)) | select(.members | length > 0))
  ' "$POLICY_DIR/key.iam.json.tmpl"
}

# Field readers: one jq per resource, tab-separated, read into named variables.
TAB=$(printf '\t')
json_fields() { # JSON JQ_ARRAY_EXPR
  printf '%s\n' "$1" | jq -r "$2 | map(. // \"\") | @tsv" || die "cannot parse JSON"
}

# Sets purpose, algorithm, protection, window from a cryptoKey; true if the first three are expected.
read_key_attrs() {
  key_fields=$(json_fields "$1" '[.purpose, .versionTemplate.algorithm, .versionTemplate.protectionLevel, .destroyScheduledDuration]')
  IFS=$TAB read -r purpose algorithm protection window <<EOT
$key_fields
EOT
  [ "$purpose" = "$KEY_PURPOSE_API" ] && [ "$algorithm" = "$KEY_ALGORITHM_API" ] && [ "$protection" = "$KEY_PROTECTION_API" ]
}

# Sets version_state, version_algorithm, version_protection from a cryptoKeyVersion; true if the last two are expected.
read_version_attrs() {
  version_fields=$(json_fields "$1" '[.state, .algorithm, .protectionLevel]')
  IFS=$TAB read -r version_state version_algorithm version_protection <<EOT
$version_fields
EOT
  [ "$version_algorithm" = "$KEY_ALGORITHM_API" ] && [ "$version_protection" = "$KEY_PROTECTION_API" ]
}

# Sets recorded_version, recorded_address, recorded_sha from record/keeper.json.
read_record() {
  record_file=$RECORD_DIR/keeper.json
  [ -f "$record_file" ] || die "$record_file missing; run address.sh"
  record_json=$(jq -c 'if type == "object" then . else error("not an object") end' "$record_file" 2>/dev/null) ||
    die "$record_file is not a JSON object"
  record_fields=$(json_fields "$record_json" '[.version, .address, .pemSha256]')
  IFS=$TAB read -r recorded_version recorded_address recorded_sha <<EOT
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

# 0 enforced, 1 not enforced, 2 could not read.
org_policy_enforced() {
  org_policy_json=$(gcloud resource-manager org-policies describe "$SA_KEY_CONSTRAINT" \
    --project="$KEY_PROJECT" --effective --format=json) || return 2
  [ "$(printf '%s\n' "$org_policy_json" | jq -r '.booleanPolicy.enforced // false')" = "true" ]
}

describe_version_1() {
  version_json=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json)
  read_version_attrs "$version_json" || die "version 1 is algorithm=$version_algorithm protectionLevel=$version_protection"
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

# Prints the expected-vs-live diff from the last policy_differs to stderr.
show_policy_diff() {
  printf '%s\n' "$desired_norm" >"$TMP/expected.json"
  printf '%s\n' "$live_norm" >"$TMP/live.json"
  diff -u "$TMP/expected.json" "$TMP/live.json" >&2 || true
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
    *) die "not an uncompressed secp256k1 SPKI" ;;
  esac
  [ ${#derive_hex} -eq 176 ] || die "unexpected DER length"
  derive_xy=$(tail -c 64 "$derive_der" | od -An -v -tx1 | tr -d ' \n')
  derive_hash=$(cast keccak "0x$derive_xy")
  derive_lower=0x$(printf '%s' "$derive_hash" | tail -c 40)
  cast to-check-sum-address "$derive_lower"
}

sha256_file() {
  openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}
