#!/bin/sh
# sh/lib.sh - shared by every script in sh/. Sourced, not executed.
#
# Provides: logging, exit codes, dependency and version checks, config loading,
# resource-name derivation, the key policy renderer and the authoritative IAM
# writer. POSIX sh only; CI runs everything under dash.
#
# Constants defined here are used by the scripts that source this file.
# shellcheck disable=SC2034

# --- exit codes ---------------------------------------------------------------
# 1 is left to `set -e` (a gcloud call or pipeline failed).
EXIT_CONFIG=2          # config.env missing, incomplete or inconsistent; bad usage
EXIT_DEPENDENCY=3      # a required tool is missing or gcloud is too old
EXIT_KEY_ATTRIBUTES=10 # key missing, or purpose/algorithm/protection level differ
EXIT_DESTROY_WINDOW=11 # destroy window is not 120 days
EXIT_VERSION_STATE=12  # version 1 is not ENABLED
EXIT_VERSION_COUNT=13  # a version other than 1 exists
EXIT_ADDRESS=14        # live public key does not derive to the recorded address
EXIT_KEY_IAM=15        # key IAM policy differs from the rendered template
EXIT_AUDIT=16          # project audit config lacks the KMS entry
EXIT_RELAY=17          # KEEPER in the relay repo differs from the record
EXIT_RECORD=18         # record/ missing or malformed

# --- constants ----------------------------------------------------------------
MIN_GCLOUD_VERSION=470.0.0
KMS_SERVICE=cloudkms.googleapis.com
KEY_PURPOSE=asymmetric-signing
KEY_PURPOSE_API=ASYMMETRIC_SIGN
KEY_ALGORITHM=ec-sign-secp256k1-sha256
KEY_ALGORITHM_API=EC_SIGN_SECP256K1_SHA256
KEY_PROTECTION=hsm
KEY_PROTECTION_API=HSM
DESTROY_WINDOW=120d          # gcloud flag value; the API maximum
DESTROY_WINDOW_API=10368000s # 120 * 86400 seconds, as the API reports it
SA_KEY_CONSTRAINT=iam.disableServiceAccountKeyCreation

# --- paths --------------------------------------------------------------------
REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
POLICY_DIR=$REPO_ROOT/policy
CONFIG_FILE=${HYDREX_CONFIG:-$REPO_ROOT/config.env}
RECORD_DIR=${HYDREX_RECORD_DIR:-$REPO_ROOT/record}

# --- logging ------------------------------------------------------------------
log() { printf '%s\n' "$*" >&2; }

# die CODE MESSAGE...
die() {
  die_code=$1
  shift
  log "error: $*"
  exit "$die_code"
}

# A temp dir removed on exit. Scripts call this once, then use $TMP.
make_tmp() {
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT INT TERM
}

# --- dependencies -------------------------------------------------------------
require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$EXIT_DEPENDENCY" "$1 not found on PATH$2"
}

# version_ge HAVE MIN: true if dotted version HAVE >= MIN.
version_ge() {
  IFS=. read -r have_1 have_2 have_3 <<EOT
$1
EOT
  IFS=. read -r min_1 min_2 min_3 <<EOT
$2
EOT
  have_1=${have_1:-0} have_2=${have_2:-0} have_3=${have_3:-0}
  min_1=${min_1:-0} min_2=${min_2:-0} min_3=${min_3:-0}
  [ "$have_1" -gt "$min_1" ] && return 0
  [ "$have_1" -lt "$min_1" ] && return 1
  [ "$have_2" -gt "$min_2" ] && return 0
  [ "$have_2" -lt "$min_2" ] && return 1
  [ "$have_3" -ge "$min_3" ]
}

require_tools() {
  require_tool gcloud " (https://cloud.google.com/sdk/docs/install)"
  require_tool openssl ""
  require_tool jq ""
  require_tool cast " (Foundry: https://getfoundry.sh)"
  gcloud_version=$(gcloud version --format=json | jq -r '."Google Cloud SDK"')
  version_ge "$gcloud_version" "$MIN_GCLOUD_VERSION" ||
    die "$EXIT_DEPENDENCY" "gcloud $gcloud_version is older than the pinned minimum $MIN_GCLOUD_VERSION"
}

# --- configuration ------------------------------------------------------------
# Reads config.env if present. Variables already in the environment win, which
# is how CI supplies them without a config file.
load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    env_KEY_PROJECT=${KEY_PROJECT:-} env_KEEPER_PROJECT=${KEEPER_PROJECT:-}
    env_LOCATION=${LOCATION:-} env_KEY_RING=${KEY_RING:-} env_KEY=${KEY:-}
    env_ADMIN_GROUP=${ADMIN_GROUP:-} env_KEEPER_SA=${KEEPER_SA:-}
    # shellcheck source=/dev/null
    . "$CONFIG_FILE"
    KEY_PROJECT=${env_KEY_PROJECT:-${KEY_PROJECT:-}}
    KEEPER_PROJECT=${env_KEEPER_PROJECT:-${KEEPER_PROJECT:-}}
    LOCATION=${env_LOCATION:-${LOCATION:-}}
    KEY_RING=${env_KEY_RING:-${KEY_RING:-}}
    KEY=${env_KEY:-${KEY:-}}
    ADMIN_GROUP=${env_ADMIN_GROUP:-${ADMIN_GROUP:-}}
    KEEPER_SA=${env_KEEPER_SA:-${KEEPER_SA:-}}
  fi
  LOCATION=${LOCATION:-us}
  KEY_RING=${KEY_RING:-hydrex-keeper}
  KEY=${KEY:-keeper}
  KEEPER_SA=${KEEPER_SA:-}

  for required in KEY_PROJECT KEEPER_PROJECT ADMIN_GROUP; do
    eval "value=\${$required:-}"
    [ -n "$value" ] ||
      die "$EXIT_CONFIG" "$required is not set; copy config.env.example to config.env and fill it in, or export it"
  done
  [ "$KEY_PROJECT" != "$KEEPER_PROJECT" ] ||
    die "$EXIT_CONFIG" "KEY_PROJECT and KEEPER_PROJECT must be different projects"
  case "$ADMIN_GROUP" in
    *@*) ;;
    *) die "$EXIT_CONFIG" "ADMIN_GROUP must be a group email address" ;;
  esac
  if [ -n "$KEEPER_SA" ]; then
    case "$KEEPER_SA" in
      *"@$KEEPER_PROJECT.iam.gserviceaccount.com") ;;
      *) die "$EXIT_CONFIG" "KEEPER_SA must be a service account in KEEPER_PROJECT ($KEEPER_PROJECT)" ;;
    esac
  fi

  KEY_RING_NAME=projects/$KEY_PROJECT/locations/$LOCATION/keyRings/$KEY_RING
  KEY_NAME=$KEY_RING_NAME/cryptoKeys/$KEY
  KEY_VERSION_NAME=$KEY_NAME/cryptoKeyVersions/1
}

# --- key IAM policy -----------------------------------------------------------
# Renders policy/key.iam.json.tmpl from config. The template lists every binding
# the key may have. When KEEPER_SA is empty, the keeper bindings are dropped, so
# before grant.sh the policy is the admin group alone. Prints JSON.
render_key_policy() {
  sed -e "s|\${ADMIN_GROUP}|$ADMIN_GROUP|g" -e "s|\${KEEPER_SA}|$KEEPER_SA|g" \
    "$POLICY_DIR/key.iam.json.tmpl" |
    jq '.bindings |= map(.members |= map(select(endswith(":") | not)) | select(.members | length > 0))'
}

# Canonical form of an IAM policy for comparison: bindings and audit configs,
# sorted, without etag or version. Reads JSON on stdin.
normalize_policy() {
  jq -S '{
    bindings: ((.bindings // [])
      | map({role, members: (.members | sort)} + (if .condition then {condition} else {} end))
      | sort_by(.role)),
    auditConfigs: ((.auditConfigs // [])
      | map({service, auditLogConfigs: (.auditLogConfigs
          | map({logType} + (if .exemptedMembers then {exemptedMembers: (.exemptedMembers | sort)} else {} end))
          | sort_by(.logType))})
      | sort_by(.service))
  }'
}

# get_iam RESOURCE gcloud-subcommand...: prints the live policy as JSON.
get_iam() {
  iam_resource=$1
  shift
  gcloud "$@" get-iam-policy "$iam_resource" --format=json
}

# write_iam_if_changed RESOURCE LIVE_JSON DESIRED_JSON gcloud-subcommand...
#
# If DESIRED differs from LIVE (ignoring etag and version) writes DESIRED in
# full, with LIVE's etag. Never merges into what is there.
write_iam_if_changed() {
  iam_resource=$1
  iam_live=$2
  iam_desired=$3
  shift 3
  iam_live_norm=$(printf '%s\n' "$iam_live" | normalize_policy)
  iam_desired_norm=$(printf '%s\n' "$iam_desired" | normalize_policy)
  if [ "$iam_live_norm" = "$iam_desired_norm" ]; then
    log "iam: $iam_resource already has the expected policy"
    return 0
  fi
  iam_etag=$(printf '%s\n' "$iam_live" | jq -r '.etag // empty')
  iam_file=$TMP/policy.json
  printf '%s\n' "$iam_desired" | jq --arg etag "$iam_etag" '.etag = $etag' >"$iam_file"
  log "iam: writing complete policy to $iam_resource"
  gcloud "$@" set-iam-policy "$iam_resource" "$iam_file" >/dev/null
}

# set_iam_authoritative RESOURCE DESIRED_JSON gcloud-subcommand...
#
# Reads the live policy and writes DESIRED if it differs.
# Example: set_iam_authoritative "$KEY_NAME" "$policy" kms keys
set_iam_authoritative() {
  set_iam_resource=$1
  set_iam_desired=$2
  shift 2
  write_iam_if_changed "$set_iam_resource" "$(get_iam "$set_iam_resource" "$@")" "$set_iam_desired" "$@"
}

# --- address derivation -------------------------------------------------------
# derive_address PEM_FILE: prints the checksummed Ethereum address of a
# secp256k1 SPKI public key. Steps, each visible: PEM -> DER (openssl), last 64
# bytes are the uncompressed X||Y (tail, od), keccak256 (cast), last 20 bytes,
# EIP-55 checksum (cast).
SECP256K1_SPKI_PREFIX=3056301006072a8648ce3d020106052b8104000a03420004

derive_address() {
  derive_der=$TMP/pub.der
  openssl pkey -pubin -in "$1" -outform DER -out "$derive_der"
  derive_hex=$(od -An -v -tx1 "$derive_der" | tr -d ' \n')
  case "$derive_hex" in
    "$SECP256K1_SPKI_PREFIX"*) ;;
    *) die "$EXIT_KEY_ATTRIBUTES" "public key is not an uncompressed secp256k1 SPKI (88-byte DER)" ;;
  esac
  [ ${#derive_hex} -eq 176 ] || die "$EXIT_KEY_ATTRIBUTES" "unexpected DER length"
  derive_xy=$(tail -c 64 "$derive_der" | od -An -v -tx1 | tr -d ' \n')
  derive_hash=$(cast keccak "0x$derive_xy")
  derive_lower=0x$(printf '%s' "$derive_hash" | tail -c 40)
  cast to-check-sum-address "$derive_lower"
}

# Sha256 of a file, hex.
sha256_file() {
  openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}
