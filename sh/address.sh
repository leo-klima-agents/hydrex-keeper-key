#!/bin/sh
# address.sh [--force]: version 1 public key -> Ethereum address -> record/.
# Refuses to overwrite a record for a different key or address unless --force.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

force=no
[ $# -le 1 ] || die "usage: $0 [--force]"
case "${1:-}" in
  "") ;;
  --force) force=yes ;;
  *) die "usage: $0 [--force]" ;;
esac

require_tools openssl
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

# Staged next to the record so the rename stays on one filesystem. JSON last.
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
