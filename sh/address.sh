#!/bin/sh
# Writes the public key of version 1 of each ROLE's key, by default every role in config.env, and its Ethereum address
# to record/ROLE.pem and ROLE.json. A record for another key or address is kept unless --force.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

force=no
roles=''
for arg in "$@"; do
  case "$arg" in
    --force) force=yes ;;
    keeper | proposer) roles="$roles $arg" ;;
    *) die "usage: ${0##*/} [--force] [ROLE...]; ROLE is keeper or proposer" ;;
  esac
done

require_tools gcloud jq openssl
require_keccak
load_config
make_tmp

roles=${roles:-$ROLES}
# Every role named must be configured before any record is written.
for role in $roles; do use_key "$role"; done

for role in $roles; do
  use_key "$role"
  key=$(find_key)
  [ -n "$key" ] || die "$KEY_NAME not found; run setup.sh"
  describe_version_1
  [ "$version_state" = "ENABLED" ] || die "$ROLE version 1 is $version_state"

  pem=$TMP/$ROLE.pem
  gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
  address=$(derive_address "$pem")

  if [ -f "$RECORD_JSON" ] && [ "$force" = no ]; then
    read_record
    if [ "$recorded_version" != "$KEY_VERSION_NAME" ] || [ "$recorded_address" != "$address" ]; then
      case "$ROLE" in
        keeper) consequence="A new key means a new module" ;;
        proposer) consequence="A new key means a new PROPOSER in hydrex-keeper's config, and funding that address" ;;
      esac
      die "$ROLE record has $recorded_address for $recorded_version; live key is $address for $KEY_VERSION_NAME. $consequence; --force to overwrite"
    fi
  fi

  # Written next to the record and renamed into place, the JSON last, so that a reader never sees a half-written record.
  mkdir -p "$RECORD_DIR"
  jq -n \
    --arg key "$KEY_NAME" \
    --arg version "$KEY_VERSION_NAME" \
    --arg algorithm "$version_algorithm" \
    --arg protectionLevel "$version_protection" \
    --arg address "$address" \
    '{key: $key, version: $version, algorithm: $algorithm, protectionLevel: $protectionLevel, address: $address}' \
    >"$RECORD_DIR/.$ROLE.json.tmp"
  cp "$pem" "$RECORD_DIR/.$ROLE.pem.tmp"
  mv "$RECORD_DIR/.$ROLE.pem.tmp" "$RECORD_PEM"
  mv "$RECORD_DIR/.$ROLE.json.tmp" "$RECORD_JSON"

  log "wrote $RECORD_PEM and $ROLE.json; commit both"
  printf '%s %s\n' "$ROLE" "$address"
done
