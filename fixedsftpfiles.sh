#!/bin/bash
# sftpfiles.sh
# Companion to sftpserver.sh: for each CSV user, create incoming/outgoing folders
#   outgoing/ComeGetMe: readable by client, contains random string
#   incoming/IAmHidden: write-only, hidden from client
# Safe to run multiple times.

set -euo pipefail

CSV_FILE=""
SFTP_GROUP="sftpusers"   # match sftpserver.sh
BASE_DIR="/sftp"         # match sftpserver.sh

usage() {
  cat <<USAGE
Usage: $0 -c users.csv [-g sftp_group] [-b /sftp]
   or: $0 users.csv
USAGE
  exit 1
}

strip_crlf_inplace() { [[ -f "$1" ]] && sed -i 's/\r$//' "$1" || true; }

# --- Parse args ---
if [[ $# -ge 1 && "$1" != "-"* && -z "${CSV_FILE}" ]]; then CSV_FILE="$1"; shift || true; fi
while getopts ":c:g:b:h" opt; do
  case "$opt" in
    c) CSV_FILE="$OPTARG" ;;
    g) SFTP_GROUP="$OPTARG" ;;
    b) BASE_DIR="$OPTARG" ;;
    h|*) usage ;;
  esac
done
[[ -n "$CSV_FILE" ]] || usage
[[ -f "$CSV_FILE" ]] || { echo "CSV not found: $CSV_FILE" >&2; exit 1; }

strip_crlf_inplace "$CSV_FILE"

command -v openssl >/dev/null 2>&1 || { echo "openssl not found" >&2; exit 1; }


while IFS= read -r line; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  if [[ "$line" =~ ^[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee][[:space:]]*, ]]; then
    continue
  fi

  user="${line%%,*}"
  user="$(echo "$user" | xargs)"
  [[ -z "$user" ]] && continue

  if ! id "$user" >/dev/null 2>&1; then
    echo "Skip: user '$user' does not exist (run sftpserver.sh first)"
    continue
  fi

  user_root="${BASE_DIR}/${user}"
  [[ -d "$user_root" ]] || { echo "Skip: ${user_root} missing"; continue; }

  incoming="${user_root}/incoming"
  outgoing="${user_root}/outgoing"

  mkdir -p "$incoming" "$outgoing"

  chown "$user":"$SFTP_GROUP" "$incoming" "$outgoing"

  chmod 300 "$incoming"   # write+execute only
  chmod 500 "$outgoing"   # read+execute only

  openssl rand -base64 12 > "${outgoing}/ComeGetMe"
  openssl rand -base64 12 > "${incoming}/IAmHidden"
  chown "$user":"$SFTP_GROUP" "${outgoing}/ComeGetMe" "${incoming}/IAmHidden"

  echo "✓ ${user}: folders & files created"
done < "$CSV_FILE"

