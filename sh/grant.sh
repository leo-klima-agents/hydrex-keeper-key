#!/bin/sh
# Writes the key's IAM policy with KEEPER_SA as its only signer. Idempotent.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

[ $# -eq 0 ] || die "usage: ${0##*/}"
require_tools gcloud jq
load_config
make_tmp

[ -n "$KEEPER_SA" ] || die "KEEPER_SA is empty"

gcloud iam service-accounts describe "$KEEPER_SA" --project="$KEEPER_PROJECT" --format="value(email)" >/dev/null ||
  die "$KEEPER_SA not found in $KEEPER_PROJECT"

key_policy=$(render_policy key.iam.json.tmpl)
set_iam "$KEY_NAME" "" "$key_policy" kms keys
