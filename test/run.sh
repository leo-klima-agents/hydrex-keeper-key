#!/bin/sh
# run.sh [--update]: every script under $TEST_SH (default dash) against
# test/fake-gcloud, diffed against test/golden/<case>.txt.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_sh=${TEST_SH:-dash}
update=no
case "$#:${1:-}" in
  0:) ;;
  1:--update) update=yes ;;
  *) printf 'usage: %s [--update]\n' "$0" >&2; exit 2 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$tmp/bin"
ln -s "$root/test/fake-gcloud" "$tmp/bin/gcloud"
PATH=$tmp/bin:$PATH
export PATH
export FAKE_ADMIN_MEMBER=user:hydrex-key-admin@example.com
export FAKE_KEEPER_SA=hydrex-keeper@hydrex-keeper-rt-test.iam.gserviceaccount.com
fixtures=$root/test/fixtures
failures=0

# run_case NAME SCENARIO CONFIG RECORD_DIR SCRIPT: runs, appends the exit code.
run_case() {
  name=$1
  log=$tmp/$name.log
  : >"$log"
  rc=0
  FAKE_GCLOUD_LOG=$log FAKE_GCLOUD_SCENARIO=$2 HYDREX_CONFIG=$root/test/config/$3.env HYDREX_RECORD_DIR=$4 \
    "$test_sh" "$root/sh/$5" >"$tmp/$name.out" 2>&1 || rc=$?
  printf 'exit=%s\n' "$rc" >>"$log"
}
golden_case() { run_case "$@" && compare "$1"; }

# capture NAME LABEL PATH: append a written file, or "(missing)", to NAME's log.
capture() {
  printf -- '--- %s ---\n' "$2" >>"$tmp/$1.log"
  if [ -f "$3" ]; then cat "$3" >>"$tmp/$1.log"; else printf '(missing)\n' >>"$tmp/$1.log"; fi
}

compare() {
  golden=$root/test/golden/$1.txt
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
    cat "$tmp/$1.out"
    failures=$((failures + 1))
  fi
}

golden_case setup-fresh fresh admin-only "$fixtures/empty" setup.sh
golden_case setup-existing existing with-keeper "$fixtures/empty" setup.sh
golden_case setup-foreign-key foreign-key admin-only "$fixtures/empty" setup.sh
golden_case setup-warn warn with-keeper "$fixtures/empty" setup.sh # a gcloud warning on stderr must not corrupt parsed output
golden_case grant-fresh admin-only with-keeper "$fixtures/empty" grant.sh

# address.sh output must equal test/fixtures/record, which the check cases read.
mkdir "$tmp/record"
run_case address existing admin-only "$tmp/record" address.sh
capture address record/keeper.json "$tmp/record/keeper.json"
capture address record/keeper.pem "$tmp/record/keeper.pem"
compare address
if [ "$update" = yes ]; then
  cp "$tmp/record/keeper.json" "$tmp/record/keeper.pem" "$fixtures/record/"
elif ! diff -u "$fixtures/record/keeper.json" "$tmp/record/keeper.json" 2>&1 ||
  ! diff -u "$fixtures/record/keeper.pem" "$tmp/record/keeper.pem" 2>&1; then
  printf 'FAIL    address: record differs from test/fixtures/record\n'
  failures=$((failures + 1))
fi

# A record for another address is refused.
mkdir "$tmp/record-other"
jq '.address = "0x0000000000000000000000000000000000000001"' "$fixtures/record/keeper.json" >"$tmp/record-other/keeper.json"
cp "$fixtures/record/keeper.pem" "$tmp/record-other/"
run_case address-refuse existing admin-only "$tmp/record-other" address.sh
capture address-refuse record/keeper.json "$tmp/record-other/keeper.json"
compare address-refuse

golden_case check-ok existing with-keeper "$fixtures/record" check.sh
golden_case check-extra-binding extra-binding with-keeper "$fixtures/record" check.sh
golden_case check-two-versions two-versions with-keeper "$fixtures/record" check.sh
golden_case check-sa-key sa-key with-keeper "$fixtures/record" check.sh
golden_case check-admin-only admin-only admin-only "$fixtures/record" check.sh

# A committed keeper.pem for another key fails the record check and skips the address check.
mkdir "$tmp/record-other-pem"
cp "$fixtures/record/keeper.json" "$tmp/record-other-pem/"
openssl ecparam -name secp256k1 -genkey -noout 2>/dev/null | openssl ec -pubout -out "$tmp/record-other-pem/keeper.pem" 2>/dev/null
golden_case check-other-pem existing with-keeper "$tmp/record-other-pem" check.sh

[ "$failures" -eq 0 ] || { printf '%s golden case(s) failed\n' "$failures"; exit 1; }
printf 'all golden cases passed\n'
