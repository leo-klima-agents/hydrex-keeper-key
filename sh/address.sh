#!/bin/sh
# sh/address.sh [--force] - public key of version 1 -> Ethereum address -> record/.
#
# PEM from KMS, DER via openssl, the final 64 bytes are X||Y (tail -c, od),
# keccak256 via cast, last 20 bytes, EIP-55 checksum via cast. Writes
# record/keeper.pem and record/keeper.json and prints the address.
#
# Refuses to replace an existing record that names a different key or address:
# the record is what check.sh and part one's KEEPER are pinned to. --force
# overrides, for the case where a new key and a new module are intended.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

force=no
case "${1:-}" in
  "") ;;
  --force) force=yes ;;
  *) die "$EXIT_CONFIG" "usage: $0 [--force]" ;;
esac

require_tools
load_config
make_tmp

version=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json)
state=$(printf '%s\n' "$version" | jq -r '.state')
algorithm=$(printf '%s\n' "$version" | jq -r '.algorithm')
protection=$(printf '%s\n' "$version" | jq -r '.protectionLevel')
[ "$state" = "ENABLED" ] || die "$EXIT_VERSION_STATE" "version 1 is $state, not ENABLED"
[ "$algorithm" = "$KEY_ALGORITHM_API" ] || die "$EXIT_KEY_ATTRIBUTES" "version 1 algorithm is $algorithm"
[ "$protection" = "$KEY_PROTECTION_API" ] || die "$EXIT_KEY_ATTRIBUTES" "version 1 protection level is $protection"

pem=$TMP/keeper.pem
gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
address=$(derive_address "$pem")
pem_sha=$(sha256_file "$pem")

existing=$RECORD_DIR/keeper.json
if [ -f "$existing" ] && [ "$force" = no ]; then
  existing_version=$(jq -r '.version // empty' "$existing")
  existing_address=$(jq -r '.address // empty' "$existing")
  existing_sha=$(jq -r '.pemSha256 // empty' "$existing")
  if [ "$existing_version" != "$KEY_VERSION_NAME" ] || [ "$existing_address" != "$address" ] || [ "$existing_sha" != "$pem_sha" ]; then
    die "$EXIT_RECORD" "$existing already records $existing_address for $existing_version; the live key derives to $address for $KEY_VERSION_NAME. A different key means a new module in part one. Re-run with --force only if that is intended."
  fi
  log "record already matches the live key"
fi

mkdir -p "$RECORD_DIR"
cp "$pem" "$RECORD_DIR/keeper.pem"
jq -n \
  --arg key "$KEY_NAME" \
  --arg version "$KEY_VERSION_NAME" \
  --arg algorithm "$algorithm" \
  --arg protectionLevel "$protection" \
  --arg address "$address" \
  --arg pemSha256 "$pem_sha" \
  '{key: $key, version: $version, algorithm: $algorithm, protectionLevel: $protectionLevel, address: $address, pemSha256: $pemSha256}' \
  >"$RECORD_DIR/keeper.json"

log "wrote $RECORD_DIR/keeper.pem and $RECORD_DIR/keeper.json; commit both"
printf '%s\n' "$address"
