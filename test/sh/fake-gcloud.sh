#!/bin/sh
# gcloud stub for the golden tests: logs each call to $FAKE_GCLOUD_LOG and answers from the $FAKE_GCLOUD_SCENARIO state.
# In the log, --output-file paths become <file> and set-iam-policy files their canonical JSON.
set -eu

: "${FAKE_GCLOUD_LOG:?}" "${FAKE_GCLOUD_SCENARIO:?}"

# Mirrors test/sh/config/key.env and the defaults in sh/lib.sh.
project=hydrex-keeper-key-test
keeper_project=hydrex-keeper-test
ring=projects/$project/locations/us/keyRings/hydrex-keeper
key=$ring/cryptoKeys/hydrex-keeper-v1
admin=user:hydrex-key-admin@example.com
keeper_sa=hydrex-keeper@$keeper_project.iam.gserviceaccount.com
email=hydrex-admin@example.com
channel=projects/$project/notificationChannels/1234567890

# What exists; ungranted is the state after setup.sh; foreign-key is another kind of key under the same name;
# drift bends the live state; list-fails denies listing keys.
has_ring=yes has_key=yes granted=yes has_audit=yes has_channel=yes has_alert=yes version_state=ENABLED
foreign=no drift=no list_fails=no
case "$FAKE_GCLOUD_SCENARIO" in
  fresh) has_ring=no has_key=no granted=no has_audit=no has_channel=no has_alert=no version_state=PENDING_GENERATION ;;
  ungranted) granted=no ;;
  existing) ;;
  foreign-key) foreign=yes ;;
  drift) drift=yes ;;
  list-fails) list_fails=yes ;;
  *)
    printf 'fake-gcloud: unknown scenario %s\n' "$FAKE_GCLOUD_SCENARIO" >&2
    exit 98
    ;;
esac

if [ "$foreign" = yes ]; then
  algorithm=EC_SIGN_P256_SHA256 protection=SOFTWARE window=86400s
else
  algorithm=EC_SIGN_SECP256K1_SHA256 protection=HSM window=10368000s
fi

# Public key of secp256k1 private key 1.
pem() {
  cat <<EOT
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEeb5mfvncu6xVoGKVzocLBwKb/NstzijZ
WfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuA==
-----END PUBLIC KEY-----
EOT
}

key_json() {
  printf '{"destroyScheduledDuration":"%s","name":"%s","purpose":"ASYMMETRIC_SIGN","versionTemplate":{"algorithm":"%s","protectionLevel":"%s"}}' \
    "$window" "$key" "$algorithm" "$protection"
}

# version_json NUMBER STATE
version_json() {
  printf '{"algorithm":"%s","name":"%s/cryptoKeyVersions/%s","protectionLevel":"%s","state":"%s"}' \
    "$algorithm" "$key" "$1" "$protection" "$2"
}

key_policy_json() {
  admin_binding='{"role":"roles/cloudkms.admin","members":["'$admin'"]}'
  keeper_bindings='{"role":"roles/cloudkms.publicKeyViewer","members":["serviceAccount:'$keeper_sa'"]},{"role":"roles/cloudkms.signer","members":["serviceAccount:'$keeper_sa'"]}'
  stray='{"role":"roles/cloudkms.viewer","members":["user:stray@example.com"]}'
  if [ "$has_key" = no ]; then
    printf '{"etag":"ACAB"}\n'
  elif [ "$granted" = no ]; then
    printf '{"bindings":[%s],"etag":"BwKeyAdmin","version":1}\n' "$admin_binding"
  elif [ "$drift" = yes ]; then
    printf '{"bindings":[%s,%s,%s],"etag":"BwKeyStray","version":1}\n' "$admin_binding" "$keeper_bindings" "$stray"
  else
    printf '{"bindings":[%s,%s],"etag":"BwKeyFull","version":1}\n' "$admin_binding" "$keeper_bindings"
  fi
}

project_policy_json() {
  bindings='{"role":"roles/owner","members":["'$admin'"]}'
  other_audit='{"service":"allServices","auditLogConfigs":[{"logType":"ADMIN_READ"}]}'
  if [ "$drift" = yes ]; then # DATA_READ turned off
    kms_audit='{"service":"cloudkms.googleapis.com","auditLogConfigs":[{"logType":"ADMIN_READ"},{"logType":"DATA_WRITE"}]}'
  else
    kms_audit='{"service":"cloudkms.googleapis.com","auditLogConfigs":[{"logType":"ADMIN_READ"},{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}'
  fi
  if [ "$has_audit" = yes ]; then
    printf '{"auditConfigs":[%s,%s],"bindings":[%s],"etag":"BwProjAudited","version":1}\n' "$other_audit" "$kms_audit" "$bindings"
  else
    printf '{"auditConfigs":[%s],"bindings":[%s],"etag":"BwProjPlain","version":1}\n' "$other_audit" "$bindings"
  fi
}

sa_policy_json() {
  if [ "$drift" = yes ]; then
    printf '{"bindings":[{"role":"roles/iam.serviceAccountTokenCreator","members":["user:stray@example.com"]}],"etag":"BwSaStray","version":1}\n'
  else
    printf '{"etag":"BwSaEmpty"}\n'
  fi
}

alert_json() {
  filter="logName=\"projects/$project/logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.serviceName=\"cloudkms.googleapis.com\" AND protoPayload.resourceName=~\"^$ring(/|\$)\""
  if [ "$drift" = yes ]; then # disabled, without a channel, and its filter edited by hand
    enabled=false channels='[]' filter='protoPayload.serviceName="cloudkms.googleapis.com"'
  else
    enabled=true channels="[\"$channel\"]"
  fi
  jq -nc --arg name "hydrex-keeper key ring changed" --arg filter "$filter" --argjson enabled "$enabled" \
    --argjson channels "$channels" --arg project "$project" \
    '{displayName: $name, enabled: $enabled, name: "projects/\($project)/alertPolicies/1", notificationChannels: $channels, conditions: [{conditionMatchedLog: {filter: $filter}}]}'
}

log_call() { printf 'gcloud %s\n' "$*" >>"$FAKE_GCLOUD_LOG"; }

# log_set_policy EXPECTED_ETAG ARGS...: checks the etag, then logs the policy file as canonical JSON.
log_set_policy() {
  expected_etag=$1
  shift
  file=$(eval "printf '%s' \"\$$#\"")
  [ "$(jq -r '.etag // ""' "$file")" = "$expected_etag" ] ||
    {
      printf 'fake-gcloud: etag %s, expected %s\n' "$(jq -r .etag "$file")" "$expected_etag" >&2
      exit 96
    }
  logged=''
  while [ $# -gt 1 ]; do
    logged="$logged $1"
    shift
  done
  log_call "${logged# } $(jq -c -S . "$file")"
}

case "$*" in
  "services enable "* | "kms keyrings create "* | "kms keys create "*)
    log_call "$@"
    ;;
  "kms keyrings list "*)
    log_call "$@"
    if [ "$has_ring" = yes ]; then printf '[{"name":"%s/keyRings/other"},{"name":"%s"}]\n' "${ring%/keyRings/*}" "$ring"; else printf '[]\n'; fi
    ;;
  "kms keys list "*)
    log_call "$@"
    [ "$list_fails" = no ] || {
      printf 'ERROR: (gcloud.kms.keys.list) PERMISSION_DENIED\n' >&2
      exit 1
    }
    if [ "$has_key" = yes ]; then printf '[{"name":"%s/cryptoKeys/other","purpose":"ENCRYPT_DECRYPT"},%s]\n' "$ring" "$(key_json)"; else printf '[]\n'; fi
    ;;
  "kms keys get-iam-policy "*)
    log_call "$@"
    key_policy_json
    ;;
  "kms keys set-iam-policy "*)
    log_set_policy "$(key_policy_json | jq -r .etag)" "$@"
    ;;
  "kms keys versions describe "*)
    log_call "$@"
    version_json 1 "$version_state"
    printf '\n'
    ;;
  "kms keys versions list "*)
    log_call "$@"
    if [ "$drift" = yes ]; then
      printf '[%s,%s]\n' "$(version_json 1 "$version_state")" "$(version_json 2 ENABLED)"
    else
      printf '[%s]\n' "$(version_json 1 "$version_state")"
    fi
    ;;
  "kms keys versions get-public-key "*)
    logged='' output_file=''
    for arg in "$@"; do
      case "$arg" in
        --output-file=*)
          logged="$logged --output-file=<file>"
          output_file=${arg#*=}
          ;;
        *) logged="$logged $arg" ;;
      esac
    done
    log_call "${logged# }"
    pem >"$output_file"
    ;;
  "projects get-iam-policy "*)
    log_call "$@"
    project_policy_json
    ;;
  "projects set-iam-policy "*)
    log_set_policy "$(project_policy_json | jq -r .etag)" "$@"
    ;;
  "beta monitoring channels list "*)
    log_call "$@"
    if [ "$has_channel" = yes ]; then
      printf '[{"name":"%s","type":"email","labels":{"email_address":"%s"}}]\n' "$channel" "$email"
    else
      printf '[]\n'
    fi
    ;;
  "beta monitoring channels create "*)
    log_call "$@"
    printf '%s\n' "$channel"
    ;;
  "monitoring policies list "*)
    log_call "$@"
    if [ "$has_alert" = yes ]; then printf '[%s]\n' "$(alert_json)"; else printf '[]\n'; fi
    ;;
  "monitoring policies create "*)
    logged=''
    for arg in "$@"; do
      case "$arg" in --policy-from-file=*) logged="$logged $(jq -c -S . "${arg#*=}")" ;; *) logged="$logged $arg" ;; esac
    done
    log_call "${logged# }"
    ;;
  "iam service-accounts describe "*)
    log_call "$@"
    printf '%s\n' "$4"
    ;;
  "iam service-accounts get-iam-policy "*)
    log_call "$@"
    sa_policy_json
    ;;
  "iam service-accounts keys list "*)
    log_call "$@"
    if [ "$drift" = yes ]; then
      printf '[{"keyType":"USER_MANAGED","name":"projects/%s/serviceAccounts/%s/keys/0123abcd"}]\n' "$keeper_project" "$keeper_sa"
    else
      printf '[]\n'
    fi
    ;;
  *)
    log_call "UNEXPECTED:" "$@"
    printf 'fake-gcloud: unexpected call: gcloud %s\n' "$*" >&2
    exit 99
    ;;
esac
