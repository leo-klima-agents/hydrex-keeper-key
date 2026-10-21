#!/bin/sh
# Runs the scripts in sh/ under $TEST_SH (default dash) against fake-gcloud.sh, and diffs the calls and output with golden/.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
test_sh=${TEST_SH:-dash}
update=no
case "$#:${1:-}" in
  0:) ;;
  1:--update) update=yes ;;
  *)
    printf 'usage: %s [--update]\n' "$0" >&2
    exit 2
    ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$tmp/bin" "$tmp/empty"
ln -s "$root/test/sh/fake-gcloud.sh" "$tmp/bin/gcloud"
ln -s "$root/test/sh/config" "$tmp/config"
PATH=$tmp/bin:$PATH
export PATH
cd "$tmp" || exit 1 # config and record directories are relative, so that no message names $tmp or $root
fixture=$root/test/sh/record
failures=0

# run_case NAME SCENARIO CONFIG RECORD SCRIPT [ARGS...]: runs SCRIPT with config/CONFIG.env and the record in directory
# RECORD; logs the gcloud calls, then the exit code and the output.
run_case() {
  name=$1
  scenario=$2
  config=$3
  record=$4
  script=$5
  shift 5
  log=$tmp/$name.log
  : >"$log"
  rc=0
  FAKE_GCLOUD_LOG=$log FAKE_GCLOUD_SCENARIO=$scenario HYDREX_CONFIG=config/$config.env \
    HYDREX_RECORD_DIR=$record "$test_sh" "$root/sh/$script" "$@" >"$tmp/$name.out" 2>&1 || rc=$?
  {
    printf 'exit=%s\n--- output ---\n' "$rc"
    cat "$tmp/$name.out"
  } >>"$log"
}

# capture NAME LABEL FILE: appends FILE, or "(missing)", to NAME's log under LABEL.
capture() {
  {
    printf -- '--- %s ---\n' "$2"
    if [ -f "$3" ]; then cat "$3"; else printf '(missing)\n'; fi
  } >>"$tmp/$1.log"
}

# compare NAME: diffs NAME's log with golden/NAME.txt, or rewrites it with --update.
compare() {
  golden=$root/test/sh/golden/$1.txt
  if grep -Eq '^exit=12[67]$' "$tmp/$1.log"; then # 126/127: broken script
    printf 'FAIL    %s: exit 126/127\n' "$1"
    cat "$tmp/$1.out"
    failures=$((failures + 1))
  elif [ "$update" = yes ]; then
    cp "$tmp/$1.log" "$golden"
    printf 'updated %s\n' "$1"
  elif [ -f "$golden" ] && diff -u "$golden" "$tmp/$1.log" >"$tmp/$1.diff"; then
    printf 'ok      %s\n' "$1"
  else
    printf 'FAIL    %s\n' "$1"
    cat "$tmp/$1.diff" 2>/dev/null || printf '(no golden %s)\n' "$golden"
    failures=$((failures + 1))
  fi
}

# golden_case NAME SCENARIO CONFIG RECORD SCRIPT [ARGS...]: run_case, then compare.
golden_case() {
  run_case "$@"
  compare "$1"
}

# compare_record NAME RECORD ROLE: diffs ROLE.json and ROLE.pem, written by NAME in directory RECORD, with
# test/sh/record, or copies them there with --update.
compare_record() {
  if [ "$update" = yes ]; then
    cp "$2/$3.json" "$2/$3.pem" "$fixture/"
  elif ! diff -u "$fixture/$3.json" "$2/$3.json" || ! diff -u "$fixture/$3.pem" "$2/$3.pem"; then
    printf 'FAIL    %s: record differs from test/sh/record\n' "$1"
    failures=$((failures + 1))
  fi
}

golden_case setup-fresh fresh admin-only empty setup.sh
golden_case setup-existing existing key empty setup.sh
golden_case setup-drift drift key empty setup.sh
golden_case setup-foreign-key foreign-key key empty setup.sh
golden_case setup-list-fails list-fails key empty setup.sh
golden_case setup-two-keys fresh two-keys empty setup.sh
golden_case setup-add-proposer no-proposer two-keys empty setup.sh
golden_case grant-fresh ungranted key empty grant.sh
golden_case grant-existing existing key empty grant.sh
golden_case grant-admin-only ungranted admin-only empty grant.sh
golden_case grant-two-keys ungranted two-keys empty grant.sh
golden_case config-leftover-key existing leftover-key empty setup.sh
golden_case config-same-key existing same-key empty setup.sh

# address.sh writes the records that the check cases read, so they must equal test/sh/record.
mkdir record
run_case address existing key record address.sh
capture address record/keeper.json record/keeper.json
capture address record/keeper.pem record/keeper.pem
compare address
compare_record address record keeper
mkdir record-both
run_case address-both existing two-keys record-both address.sh
capture address-both record/keeper.json record-both/keeper.json
capture address-both record/keeper.pem record-both/keeper.pem
capture address-both record/proposer.json record-both/proposer.json
capture address-both record/proposer.pem record-both/proposer.pem
compare address-both
compare_record address-both record-both keeper
compare_record address-both record-both proposer
golden_case address-bad-arg existing key empty address.sh --later
golden_case address-no-proposer existing key empty address.sh proposer

# A record for another address is refused, unless forced.
mkdir record-other
jq '.address = "0x0000000000000000000000000000000000000001"' "$fixture/keeper.json" >record-other/keeper.json
cp "$fixture/keeper.pem" record-other/
run_case address-refuse existing key record-other address.sh
capture address-refuse record/keeper.json record-other/keeper.json
compare address-refuse
run_case address-force existing key record-other address.sh --force
capture address-force record/keeper.json record-other/keeper.json
compare address-force

# A role named alone leaves the other's record, here for another address, as it is, even with --force.
mkdir record-one
jq '.address = "0x0000000000000000000000000000000000000001"' "$fixture/keeper.json" >record-one/keeper.json
cp "$fixture/keeper.pem" record-one/
run_case address-proposer existing two-keys record-one address.sh proposer
capture address-proposer record/keeper.json record-one/keeper.json
capture address-proposer record/proposer.json record-one/proposer.json
compare address-proposer
jq '.address = "0x0000000000000000000000000000000000000002"' "$fixture/proposer.json" >record-one/proposer.json
run_case address-refuse-proposer existing two-keys record-one address.sh proposer
capture address-refuse-proposer record/proposer.json record-one/proposer.json
compare address-refuse-proposer
run_case address-force-proposer existing two-keys record-one address.sh --force proposer
capture address-force-proposer record/keeper.json record-one/keeper.json
capture address-force-proposer record/proposer.json record-one/proposer.json
compare address-force-proposer

golden_case check-ok existing key record check.sh
golden_case check-drift drift key record check.sh
golden_case check-fresh fresh key record check.sh
golden_case check-list-fails list-fails key record check.sh
golden_case check-foreign-key foreign-key key record check.sh
golden_case check-admin-only ungranted admin-only record check.sh

# A keeper.pem for another key: the public key of secp256k1 private key 2.
mkdir record-other-pem
cp "$fixture/keeper.json" record-other-pem/
cat >record-other-pem/keeper.pem <<PEM
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAExgR/lEHtfW0wRUBulcB82Fx3jkuM7zyn
q6wJuVxwnuUa4Wj+pj3DOaPFhBlGbOru9/YyZTJm0OEjZDGpUM/lKg==
-----END PUBLIC KEY-----
PEM
golden_case check-other-pem existing key record-other-pem check.sh

golden_case check-two-keys existing two-keys record-both check.sh
golden_case check-drift-two-keys drift two-keys record-both check.sh
golden_case check-proposer-missing existing two-keys record check.sh # record holds the keeper's alone
golden_case check-proposer-unset existing key record-both check.sh

# A proposer record for the keeper's public key and address: consistent in itself, but not the live key's.
mkdir record-proposer-mismatch
cp "$fixture/keeper.json" "$fixture/keeper.pem" record-proposer-mismatch/
jq --slurpfile keeper "$fixture/keeper.json" '.address = $keeper[0].address' "$fixture/proposer.json" \
  >record-proposer-mismatch/proposer.json
cp "$fixture/keeper.pem" record-proposer-mismatch/proposer.pem
golden_case check-proposer-mismatch existing two-keys record-proposer-mismatch check.sh

[ "$failures" -eq 0 ] || {
  printf '%s golden case(s) failed\n' "$failures"
  exit 1
}
printf 'all golden cases passed\n'
