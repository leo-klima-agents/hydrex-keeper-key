#!/bin/sh
# test/run.sh [--update] - run every script under dash against test/fake-gcloud
# and compare the recorded gcloud call sequence (plus exit code, plus any files
# written) with test/golden/<case>.txt. --update rewrites the goldens.
#
# TEST_SH picks the shell (default dash). Needs jq, openssl and cast on PATH;
# gcloud must not be needed, the fake shadows it.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_sh=${TEST_SH:-dash}
update=no
[ "${1:-}" = "--update" ] && update=yes

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$tmp/bin"
ln -s "$root/test/fake-gcloud" "$tmp/bin/gcloud"
PATH=$tmp/bin:$PATH
export PATH

# Nothing from the caller's environment may leak into the scripts under test.
unset KEY_PROJECT KEEPER_PROJECT LOCATION KEY_RING KEY ADMIN_GROUP KEEPER_SA
export FAKE_ADMIN_GROUP=hydrex-key-admins@example.com
export FAKE_KEEPER_SA=hydrex-keeper@hydrex-keeper-rt-test.iam.gserviceaccount.com

failures=0
compare() { # compare NAME ACTUAL_FILE
  golden=$root/test/golden/$1.txt
  if [ "$update" = yes ]; then
    cp "$2" "$golden"
    printf 'updated %s\n' "$1"
  elif [ -f "$golden" ] && diff -u "$golden" "$2" >"$tmp/$1.diff"; then
    printf 'ok      %s\n' "$1"
  else
    printf 'FAIL    %s\n' "$1"
    cat "$tmp/$1.diff" 2>/dev/null || printf '(no golden %s)\n' "$golden"
    printf -- '--- script output ---\n'
    cat "$tmp/$1.out"
    printf -- '---------------------\n'
    failures=$((failures + 1))
  fi
}

# run_case NAME SCENARIO CONFIG RECORD_DIR SCRIPT [ARGS...]
run_case() {
  name=$1 scenario=$2 config=$3 record_dir=$4 script=$5
  shift 5
  log=$tmp/$name.log
  : >"$log"
  rc=0
  FAKE_GCLOUD_LOG=$log FAKE_GCLOUD_SCENARIO=$scenario \
    HYDREX_CONFIG=$root/test/config/$config.env HYDREX_RECORD_DIR=$record_dir \
    "$test_sh" "$root/sh/$script" "$@" >"$tmp/$name.out" 2>&1 || rc=$?
  printf 'exit=%s\n' "$rc" >>"$log"
}

fixtures=$root/test/fixtures

# setup.sh
run_case setup-fresh fresh admin-only "$fixtures/empty" setup.sh
compare setup-fresh "$tmp/setup-fresh.log"
run_case setup-existing existing with-keeper "$fixtures/empty" setup.sh
compare setup-existing "$tmp/setup-existing.log"
run_case setup-repair repair with-keeper "$fixtures/empty" setup.sh
compare setup-repair "$tmp/setup-repair.log"
run_case setup-foreign-key foreign-key admin-only "$fixtures/empty" setup.sh
compare setup-foreign-key "$tmp/setup-foreign-key.log"
run_case setup-short-window short-window admin-only "$fixtures/empty" setup.sh
compare setup-short-window "$tmp/setup-short-window.log"

# grant.sh
run_case grant-fresh admin-only with-keeper "$fixtures/empty" grant.sh
compare grant-fresh "$tmp/grant-fresh.log"
run_case grant-existing existing with-keeper "$fixtures/empty" grant.sh
compare grant-existing "$tmp/grant-existing.log"
run_case grant-no-keeper-sa existing admin-only "$fixtures/empty" grant.sh
compare grant-no-keeper-sa "$tmp/grant-no-keeper-sa.log"

# address.sh: the log also carries the files it wrote, and they must equal
# test/fixtures/record, which the check cases read.
mkdir "$tmp/record"
run_case address existing admin-only "$tmp/record" address.sh
{
  printf -- '--- stdout ---\n'
  grep -v '^wrote ' "$tmp/address.out" || true
  printf -- '--- record/keeper.json ---\n'
  cat "$tmp/record/keeper.json"
  printf -- '--- record/keeper.pem ---\n'
  cat "$tmp/record/keeper.pem"
} >>"$tmp/address.log" 2>&1
compare address "$tmp/address.log"
if [ "$update" = yes ]; then
  cp "$tmp/record/keeper.json" "$tmp/record/keeper.pem" "$fixtures/record/"
elif ! diff -u "$fixtures/record/keeper.json" "$tmp/record/keeper.json" || ! diff -u "$fixtures/record/keeper.pem" "$tmp/record/keeper.pem"; then
  printf 'FAIL    address: record differs from test/fixtures/record\n'
  failures=$((failures + 1))
fi
# Re-running against the same key is fine; against a different key it refuses
# unless --force is given.
run_case address-same-key existing admin-only "$tmp/record" address.sh
compare address-same-key "$tmp/address-same-key.log"
mkdir "$tmp/record-other"
cp "$fixtures/record/keeper.json" "$fixtures/record/keeper.pem" "$tmp/record-other/"
run_case address-other-key other-key admin-only "$tmp/record-other" address.sh
compare address-other-key "$tmp/address-other-key.log"
run_case address-other-key-force other-key admin-only "$tmp/record-other" address.sh --force
{
  printf -- '--- record/keeper.json ---\n'
  cat "$tmp/record-other/keeper.json"
  printf -- '--- record/keeper.pem ---\n'
  cat "$tmp/record-other/keeper.pem"
} >>"$tmp/address-other-key-force.log"
compare address-other-key-force "$tmp/address-other-key-force.log"
# A record for the same key whose PEM bytes differ (gcloud formatting change)
# is refreshed, not refused.
mkdir "$tmp/record-stale-pem"
cp "$fixtures/record/keeper.pem" "$tmp/record-stale-pem/"
jq '.pemSha256 = "0000"' "$fixtures/record/keeper.json" >"$tmp/record-stale-pem/keeper.json"
run_case address-refresh-pem existing admin-only "$tmp/record-stale-pem" address.sh
printf -- '--- record/keeper.json ---\n' >>"$tmp/address-refresh-pem.log"
cat "$tmp/record-stale-pem/keeper.json" >>"$tmp/address-refresh-pem.log"
compare address-refresh-pem "$tmp/address-refresh-pem.log"
mkdir "$tmp/record-malformed"
printf 'not json\n' >"$tmp/record-malformed/keeper.json"
cp "$fixtures/record/keeper.pem" "$tmp/record-malformed/"
run_case address-malformed-record existing admin-only "$tmp/record-malformed" address.sh
compare address-malformed-record "$tmp/address-malformed-record.log"
run_case address-bad-args existing admin-only "$tmp/record" address.sh --force extra
compare address-bad-args "$tmp/address-bad-args.log"
run_case address-pending fresh admin-only "$tmp/record" address.sh
compare address-pending "$tmp/address-pending.log"

# check.sh: each drift has its own exit code.
run_case check-ok existing with-keeper "$fixtures/record" check.sh "$fixtures/relay-ok"
compare check-ok "$tmp/check-ok.log"
run_case check-no-record existing with-keeper "$fixtures/empty" check.sh
compare check-no-record "$tmp/check-no-record.log"
run_case check-malformed-record existing with-keeper "$tmp/record-malformed" check.sh
compare check-malformed-record "$tmp/check-malformed-record.log"
run_case check-foreign-key foreign-key with-keeper "$fixtures/record" check.sh
compare check-foreign-key "$tmp/check-foreign-key.log"
run_case check-window-and-disabled window-and-disabled with-keeper "$fixtures/record" check.sh
compare check-window-and-disabled "$tmp/check-window-and-disabled.log"
run_case check-two-versions two-versions with-keeper "$fixtures/record" check.sh
compare check-two-versions "$tmp/check-two-versions.log"
run_case check-other-key other-key with-keeper "$fixtures/record" check.sh
compare check-other-key "$tmp/check-other-key.log"
run_case check-extra-binding extra-binding with-keeper "$fixtures/record" check.sh
compare check-extra-binding "$tmp/check-extra-binding.log"
run_case check-before-grant admin-only admin-only "$fixtures/record" check.sh
compare check-before-grant "$tmp/check-before-grant.log"
run_case check-config-behind-grant existing admin-only "$fixtures/record" check.sh
compare check-config-behind-grant "$tmp/check-config-behind-grant.log"
run_case check-missing-config existing missing "$fixtures/record" check.sh
compare check-missing-config "$tmp/check-missing-config.log"
run_case check-no-audit no-audit with-keeper "$fixtures/record" check.sh
compare check-no-audit "$tmp/check-no-audit.log"
run_case check-relay-mismatch existing with-keeper "$fixtures/record" check.sh "$fixtures/relay-bad"
compare check-relay-mismatch "$tmp/check-relay-mismatch.log"
run_case check-relay-decoy existing with-keeper "$fixtures/record" check.sh "$fixtures/relay-decoy"
compare check-relay-decoy "$tmp/check-relay-decoy.log"
run_case check-relay-ambiguous existing with-keeper "$fixtures/record" check.sh "$fixtures/relay-ambiguous"
compare check-relay-ambiguous "$tmp/check-relay-ambiguous.log"

if [ "$failures" -ne 0 ]; then
  printf '%s golden case(s) failed\n' "$failures"
  exit 1
fi
printf 'all golden cases passed\n'
