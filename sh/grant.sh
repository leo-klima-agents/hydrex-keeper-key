#!/bin/sh
# sh/grant.sh - the one cross-project grant. Idempotent.
#
# Writes the complete key IAM policy from policy/key.iam.json.tmpl with
# KEEPER_SA (the Cloud Run job's service account in KEEPER_PROJECT) as
# roles/cloudkms.signer and roles/cloudkms.publicKeyViewer. setup.sh writes
# the same template, so once KEEPER_SA is in config.env either script leaves
# the same policy behind.
set -eu
script_dir=$(dirname -- "$0")
# shellcheck source=sh/lib.sh
. "$script_dir/lib.sh"

require_tools
load_config
make_tmp

[ -n "$KEEPER_SA" ] ||
  die "$EXIT_CONFIG" "KEEPER_SA is empty. Set it in config.env once part three has created the job's service account."

# Catch a typo before it lands in the policy.
gcloud iam service-accounts describe "$KEEPER_SA" --project="$KEEPER_PROJECT" --format="value(email)" >/dev/null ||
  die 1 "service account $KEEPER_SA not found in $KEEPER_PROJECT"

log "granting roles/cloudkms.signer and roles/cloudkms.publicKeyViewer on $KEY_NAME to $KEEPER_SA"
key_policy=$(render_key_policy)
set_iam_authoritative "$KEY_NAME" "$key_policy" kms keys
log "done"
