#!/bin/sh
# Writes the public key of key version 1 and its Ethereum address to record/. A record for another key or address is
# kept unless --force.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

force=no
for arg in "$@"; do
  case "$arg" in
    --force) force=yes ;;
    *) die "usage: ${0##*/} [--force]" ;;
  esac
done

require_tools gcloud jq openssl
require_keccak
load_config
make_tmp

key=$(find_key)
[ -n "$key" ] || die "$KEY_NAME not found; run setup.sh"
describe_version_1
[ "$version_state" = "ENABLED" ] || die "version 1 is $version_state"

pem=$TMP/keeper.pem
gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
address=$(derive_address "$pem")

if [ -f "$RECORD_DIR/keeper.json" ] && [ "$force" = no ]; then
  read_record
  if [ "$recorded_version" != "$KEY_VERSION_NAME" ] || [ "$recorded_address" != "$address" ]; then
    die "record has $recorded_address for $recorded_version; live key is $address for $KEY_VERSION_NAME. A new key means a new module; --force to overwrite"
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
  >"$RECORD_DIR/.keeper.json.tmp"
cp "$pem" "$RECORD_DIR/.keeper.pem.tmp"
mv "$RECORD_DIR/.keeper.pem.tmp" "$RECORD_DIR/keeper.pem"
mv "$RECORD_DIR/.keeper.json.tmp" "$RECORD_DIR/keeper.json"

log "wrote $RECORD_DIR/keeper.pem and keeper.json; commit both"
printf '%s\n' "$address"
