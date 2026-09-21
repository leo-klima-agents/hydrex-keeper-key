#!/bin/sh
# sh/address.sh - public key of version 1 -> Ethereum address -> record/.
#
# PEM from KMS, DER via openssl, the final 64 bytes are X||Y (tail -c, od),
# keccak256 via cast, last 20 bytes, EIP-55 checksum via cast. Writes
# record/keeper.pem and record/keeper.json and prints the address.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

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

mkdir -p "$RECORD_DIR"
cp "$pem" "$RECORD_DIR/keeper.pem"
jq -n \
  --arg key "$KEY_NAME" \
  --arg version "$KEY_VERSION_NAME" \
  --arg algorithm "$algorithm" \
  --arg protectionLevel "$protection" \
  --arg address "$address" \
  --arg pemSha256 "$(sha256_file "$pem")" \
  '{key: $key, version: $version, algorithm: $algorithm, protectionLevel: $protectionLevel, address: $address, pemSha256: $pemSha256}' \
  >"$RECORD_DIR/keeper.json"

log "wrote $RECORD_DIR/keeper.pem and $RECORD_DIR/keeper.json; commit both"
printf '%s\n' "$address"
