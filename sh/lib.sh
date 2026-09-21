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
EXIT_KEY_ATTRIBUTES=10 # key not found, or purpose/algorithm/protection level differ
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
DESTROY_WINDOW=120d          # gcloud flag value; the API maximum. Immutable once created.
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
  trap 'rm -rf "$TMP"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# --- dependencies -------------------------------------------------------------
require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$EXIT_DEPENDENCY" "$1 not found on PATH$2"
}

# version_ge HAVE MIN: true if dotted version HAVE >= MIN. Anything that is not
# digits and dots is not a version and never satisfies the pin.
version_ge() {
  case "$1$2" in "" | *[!0-9.]*) return 1 ;; esac
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

# shellcheck disable=SC2120
# require_tools [EXTRA...]: gcloud and jq always; address.sh and check.sh
# also pass openssl and cast, which the IAM scripts never use.
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
    "" | *[!0-9.]*) die "$EXIT_DEPENDENCY" "could not parse the gcloud version from 'gcloud version --format=json' (got '$gcloud_version')" ;;
  esac
  version_ge "$gcloud_version" "$MIN_GCLOUD_VERSION" ||
    die "$EXIT_DEPENDENCY" "gcloud $gcloud_version is older than the pinned minimum $MIN_GCLOUD_VERSION"
}

# --- configuration ------------------------------------------------------------
# Reads config.env when it exists; the file is authoritative, so a stray KEY or
# LOCATION in the caller's environment cannot redirect a script to another key.
# Without a file, variables come from the environment, which is how CI runs.
load_config() {
  if [ -n "${HYDREX_CONFIG:-}" ] && [ ! -f "$CONFIG_FILE" ]; then
    die "$EXIT_CONFIG" "HYDREX_CONFIG points at $CONFIG_FILE, which does not exist"
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
  jq --arg admin "$ADMIN_GROUP" --arg keeper "$KEEPER_SA" '
    walk(if type == "string"
         then (split("${ADMIN_GROUP}") | join($admin)) | (split("${KEEPER_SA}") | join($keeper))
         else . end)
    | .bindings |= map(.members |= map(select(endswith(":") | not)) | select(.members | length > 0))
  ' "$POLICY_DIR/key.iam.json.tmpl"
}

# Field readers. Each runs one jq over the resource and reads the fields line
# by line. jq emits a final "end" line so the last field may be empty without
# read hitting EOF (which would return 1 and, at top level, trip set -e).

# read_key_attributes KEY_JSON: sets purpose, algorithm, protection and window
# from a cryptoKey resource, and returns 0 if purpose, algorithm and protection
# level are the expected ones.
read_key_attributes() {
  key_fields=$(printf '%s\n' "$1" | jq -r '
    (.purpose // ""), (.versionTemplate.algorithm // ""),
    (.versionTemplate.protectionLevel // ""), (.destroyScheduledDuration // ""), "end"')
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

# read_version_attributes VERSION_JSON: sets version_state, version_algorithm
# and version_protection from a cryptoKeyVersion resource, and returns 0 if the
# algorithm and protection level are the expected ones. The key's template is
# mutable; these are what the material actually has.
read_version_attributes() {
  version_fields=$(printf '%s\n' "$1" | jq -r '
    (.state // ""), (.algorithm // ""), (.protectionLevel // ""), "end"')
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

# read_record: loads record/keeper.json into recorded_version, recorded_address
# and recorded_sha, or dies with EXIT_RECORD when the file is missing, empty,
# not a JSON object, or has a field that is not a plain single-line string.
# Missing fields read as empty; callers decide what that means.
read_record() {
  record_file=$RECORD_DIR/keeper.json
  [ -f "$record_file" ] || die "$EXIT_RECORD" "$record_file missing; run address.sh first"
  record_fields=$(jq -r '
    def field: (. // "") | if type != "string" or test("\\p{Cc}") then error("bad field") else . end;
    if type == "object" then (.version | field), (.address | field), (.pemSha256 | field), "end"
    else error("not a JSON object") end' "$record_file" 2>/dev/null) ||
    die "$EXIT_RECORD" "$record_file is not a JSON object with plain string fields"
  [ -n "$record_fields" ] || die "$EXIT_RECORD" "$record_file is empty"
  {
    read -r recorded_version
    read -r recorded_address
    read -r recorded_sha
  } <<EOT
$record_fields
EOT
}

# --- live key lookups ---------------------------------------------------------
# find_key: prints the cryptoKey resource as JSON, or nothing when the key does
# not exist. A filtered list makes absence a structured empty result instead of
# an error message to parse; any other failure is gcloud's, exit 1.
find_key() {
  find_key_list=$(gcloud kms keys list --project="$KEY_PROJECT" --location="$LOCATION" --keyring="$KEY_RING" \
    --filter="name=$KEY_NAME" --format=json)
  printf '%s\n' "$find_key_list" | jq -c --arg name "$KEY_NAME" '.[] | select(.name == $name)'
}

# describe_version_1: sets version_state, version_algorithm and
# version_protection from the live version 1, and dies with
# EXIT_KEY_ATTRIBUTES if its algorithm or protection level are not the
# expected ones.
describe_version_1() {
  version_json=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json)
  read_version_attributes "$version_json" ||
    die "$EXIT_KEY_ATTRIBUTES" "version 1 is algorithm=$version_algorithm protectionLevel=$version_protection"
}

# strip_solidity_comments: stdin -> stdout with // and /* */ comments and
# string literals removed and lines joined with spaces, so an assignment can
# be matched wherever a formatter wrapped it. One pass, one state machine.
strip_solidity_comments() {
  awk '
    BEGIN { state = "code" }
    {
      line = $0 " "
      n = length(line)
      for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        d = substr(line, i, 2)
        if (state == "code") {
          if (d == "//") { state = "line"; break }
          else if (d == "/*") { state = "block"; i++ }
          else if (c == "\"" || c == "\047") { quote = c; state = "string" }
          else printf "%s", c
        } else if (state == "block") {
          if (d == "*/") { state = "code"; i++; printf " " }
        } else if (state == "string") {
          if (c == "\\") i++
          else if (c == quote) state = "code"
        }
      }
      if (state == "line") state = "code"
    }
    END { printf "\n" }'
}

# Canonical form of an IAM policy for comparison: bindings and audit configs,
# sorted, without etag or version. Reads JSON on stdin.
normalize_policy() {
  jq -S '{
    bindings: ((.bindings // [])
      | map({role, members: ((.members // []) | sort)} + (if .condition then {condition} else {} end))
      | sort_by(.role)),
    auditConfigs: ((.auditConfigs // [])
      | map({service, auditLogConfigs: ((.auditLogConfigs // [])
          | map({logType} + (if .exemptedMembers then {exemptedMembers: (.exemptedMembers | sort)} else {} end))
          | sort_by(.logType))})
      | sort_by(.service))
  }'
}

# policy_differs LIVE_JSON DESIRED_JSON: returns 0 when the two policies differ
# in bindings or audit configs (etag and version ignored). Leaves the canonical
# forms in live_norm and desired_norm for reporting.
policy_differs() {
  live_norm=$(printf '%s\n' "$1" | normalize_policy)
  desired_norm=$(printf '%s\n' "$2" | normalize_policy)
  [ "$live_norm" != "$desired_norm" ]
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
  if ! policy_differs "$iam_live" "$iam_desired"; then
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
  # Assigned on its own line so a failed read aborts under set -e instead of
  # becoming an empty LIVE (and an empty etag) inside an argument.
  set_iam_live=$(get_iam "$set_iam_resource" "$@")
  write_iam_if_changed "$set_iam_resource" "$set_iam_live" "$set_iam_desired" "$@"
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
