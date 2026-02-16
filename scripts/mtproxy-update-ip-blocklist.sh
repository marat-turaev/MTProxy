#!/usr/bin/env bash
set -euo pipefail

# Fetches FireHOL lists, normalizes entries (IP/CIDR), and atomically updates
# the local MTProxy blocklist file.

LOCK_FILE="${LOCK_FILE:-/var/lock/mtproxy-ip-blocklist.lock}"
DST="${DST:-/etc/telegram/ip-blocklist.txt}"

URLS=(
  "${FIREHOL_URL1:-https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset}"
  "${FIREHOL_URL2:-https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset}"
)

mkdir -p "$(dirname "$LOCK_FILE")" "$(dirname "$DST")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  exit 0
fi

TMP_RAW="$(mktemp /tmp/mtproxy-ipbl.raw.XXXXXX)"
TMP_NEW="$(mktemp /tmp/mtproxy-ipbl.new.XXXXXX)"
trap 'rm -f "$TMP_RAW" "$TMP_NEW"' EXIT

for u in "${URLS[@]}"; do
  curl -fsSL --max-time 45 "$u" >>"$TMP_RAW"
  printf '\n' >>"$TMP_RAW"
done

awk '
{
  sub(/\r$/, "");
  sub(/#.*/, "");
  gsub(/^[ \t]+|[ \t]+$/, "");
  if ($0 == "") next;
  print;
}
' "$TMP_RAW" |
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9A-Fa-f:]+(/[0-9]{1,3})?$' |
sort -u >"$TMP_NEW"

if [ ! -s "$TMP_NEW" ]; then
  echo "blocklist update produced empty file" >&2
  exit 1
fi

install -m 0644 "$TMP_NEW" "$DST.new"
mv -f "$DST.new" "$DST"
