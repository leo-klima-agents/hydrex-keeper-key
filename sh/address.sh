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
[ $# -le 1 ] || die "$EXIT_CONFIG" "usage: $0 [--force]"
case "${1:-}" in
  "") ;;
  --force) force=yes ;;
  *) die "$EXIT_CONFIG" "usage: $0 [--force]" ;;
esac

require_tools openssl cast
load_config
make_tmp

version=$(gcloud kms keys versions describe "$KEY_VERSION_NAME" --format=json)
read_version_attributes "$version" ||
  die "$EXIT_KEY_ATTRIBUTES" "version 1 is algorithm=$version_algorithm protectionLevel=$version_protection"
[ "$version_state" = "ENABLED" ] || die "$EXIT_VERSION_STATE" "version 1 is $version_state, not ENABLED"

pem=$TMP/keeper.pem
gcloud kms keys versions get-public-key "$KEY_VERSION_NAME" --output-file="$pem"
address=$(derive_address "$pem")
pem_sha=$(sha256_file "$pem")

if [ -f "$RECORD_DIR/keeper.json" ] && [ "$force" = no ]; then
  read_record
  if [ "$recorded_version" != "$KEY_VERSION_NAME" ] || [ "$recorded_address" != "$address" ]; then
    die "$EXIT_RECORD" "$RECORD_DIR/keeper.json already records $recorded_address for $recorded_version; the live key derives to $address for $KEY_VERSION_NAME. A different key means a new module in part one. Re-run with --force only if that is intended."
  fi
  # Judged on the files as they are on disk, so a deleted or edited keeper.pem
  # is regenerated rather than trusted from the recorded hash.
  if [ -f "$RECORD_DIR/keeper.pem" ] && [ "$recorded_sha" = "$pem_sha" ] &&
    [ "$(sha256_file "$RECORD_DIR/keeper.pem")" = "$pem_sha" ]; then
    log "record already matches the live key; nothing to write"
    printf '%s\n' "$address"
    exit 0
  fi
  log "record names the same key and address; refreshing keeper.pem and pemSha256"
fi

mkdir -p "$RECORD_DIR"
cp "$pem" "$RECORD_DIR/keeper.pem"
jq -n \
  --arg key "$KEY_NAME" \
  --arg version "$KEY_VERSION_NAME" \
  --arg algorithm "$version_algorithm" \
  --arg protectionLevel "$version_protection" \
  --arg address "$address" \
  --arg pemSha256 "$pem_sha" \
  '{key: $key, version: $version, algorithm: $algorithm, protectionLevel: $protectionLevel, address: $address, pemSha256: $pemSha256}' \
  >"$RECORD_DIR/keeper.json"

log "wrote $RECORD_DIR/keeper.pem and $RECORD_DIR/keeper.json; commit both"
printf '%s\n' "$address"
