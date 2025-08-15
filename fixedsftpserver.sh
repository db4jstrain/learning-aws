#!/bin/bash
# sftpserver.sh (dynamic, multi-user) — quiet & SFTP-only
# Creates/updates SFTP-only users from CSV: username,public_key_or_pubkey_path
# Works on Amazon Linux 2/2023, Ubuntu/Debian, RHEL/Rocky

set -euo pipefail

# ---------- Defaults ----------
CSV_FILE=""
SFTP_GROUP="sftpusers"
BASE_DIR="/sftp"
SSH_PORT="22"
SSHD_CFG="/etc/ssh/sshd_config"
MARK_BEGIN="# >>> SFTP CSV AUTO-CONFIG BEGIN <<<"
MARK_END="# >>> SFTP CSV AUTO-CONFIG END <<<"

usage() {
  cat <<USAGE
Usage: $0 -c users.csv [-g sftp_group] [-b /sftp] [-p 22]
   or: $0 users.csv

CSV (header optional):
  username,ssh-ed25519 AAAAC3NzaC1lZ... comment
  username,/absolute/path/to/key.pub
USAGE
  exit 1
}

need_root() { [[ ${EUID} -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }; }

# ---------- Helpers ----------
install_pkg_if_missing() {
  local pkg="$1"
  if command -v dnf >/dev/null 2>&1; then dnf -qy install "$pkg" || true
  elif command -v yum >/dev/null 2>&1; then yum -y install "$pkg" || true
  elif command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y "$pkg"
  fi
}

strip_crlf_inplace() { [[ -f "$1" ]] && sed -i 's/\r$//' "$1" || true; }

restore_latest_sshd_backup() {
  local latest
  latest="$(ls -t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -1 || true)"
  [[ -n "${latest:-}" ]] || return 1
  cp -a "$latest" "$SSHD_CFG"
  echo "Restored sshd_config from backup: $latest"
}

validate_and_restart_sshd() {
  strip_crlf_inplace "$SSHD_CFG"
  if ! sshd -t 2>/tmp/sshd_t_err; then
    echo "sshd_config validation failed:" >&2
    cat /tmp/sshd_t_err >&2
    echo "Attempting rollback..." >&2
    restore_latest_sshd_backup || { echo "No backup to restore." >&2; return 1; }
    strip_crlf_inplace "$SSHD_CFG"
    sshd -t
  fi

  if systemctl list-units --type=service 2>/dev/null | grep -qE 'sshd\.service'; then
    systemctl restart sshd
  elif systemctl list-units --type=service 2>/dev/null | grep -qE 'ssh\.service'; then
    systemctl restart ssh
  else
    service sshd restart 2>/dev/null || service ssh restart 2>/dev/null || true
  fi
}

# Insert a single line BEFORE the first Match block (keeps it global)
insert_before_first_match() {
  local ins_line="$1"
  if grep -qE '^\s*Match\s' "$SSHD_CFG"; then
    awk -v ins="$ins_line" '
      BEGIN{done=0}
      /^\s*Match[[:space:]]/ && !done {print ins; done=1}
      {print}
      END{if(!done) print ins}
    ' "$SSHD_CFG" > "${SSHD_CFG}.new" && mv "${SSHD_CFG}.new" "$SSHD_CFG"
  else
    printf '%s\n' "$ins_line" >> "$SSHD_CFG"
  fi
}

ensure_sshd_chroot_block() {
  # Backup once per run
  cp -a "$SSHD_CFG" "${SSHD_CFG}.bak.$(date +%F_%H%M%S)"
  strip_crlf_inplace "$SSHD_CFG"

  # --- Normalize GLOBAL directives (must be before any Match)
  # Comment out existing lines to avoid duplicates/contradictions
  sed -i 's/^\s*Subsystem\s\+sftp\s\+.*/# &/I' "$SSHD_CFG"
  sed -i 's/^\s*Port\s\+.*/# &/I' "$SSHD_CFG"
  sed -i 's/^\s*PasswordAuthentication\s\+.*/# &/I' "$SSHD_CFG"
  sed -i 's/^\s*PrintMotd\s\+.*/# &/I' "$SSHD_CFG"
  sed -i 's/^\s*PrintLastLog\s\+.*/# &/I' "$SSHD_CFG"
  sed -i 's/^\s*PermitUserEnvironment\s\+.*/# &/I' "$SSHD_CFG"

  insert_before_first_match "Subsystem sftp internal-sftp"
  insert_before_first_match "PasswordAuthentication no"
  insert_before_first_match "Port ${SSH_PORT}"
  # Quiet typical interactive-only noise (safe for SFTP)
  insert_before_first_match "PrintMotd no"
  insert_before_first_match "PrintLastLog no"
  insert_before_first_match "PermitUserEnvironment no"

  # --- Remove any previous managed block
  if grep -qF "$MARK_BEGIN" "$SSHD_CFG"; then
    awk -v m1="$MARK_BEGIN" -v m2="$MARK_END" '
      $0==m1 {skip=1}
      skip && $0==m2 {skip=0; next}
      !skip {print}
    ' "$SSHD_CFG" > "${SSHD_CFG}.new"
    mv "${SSHD_CFG}.new" "$SSHD_CFG"
  fi

  # --- Append fresh managed Match block (only allowed directives)
  cat >> "$SSHD_CFG" <<EOF

$MARK_BEGIN
# SFTP-only chroot for group ${SFTP_GROUP}
Match Group ${SFTP_GROUP}
    ChrootDirectory ${BASE_DIR}/%u
    ForceCommand internal-sftp
    X11Forwarding no
    AllowTcpForwarding no
    PermitTunnel no
$MARK_END
EOF
}

ensure_group_and_basedir() {
  getent group "$SFTP_GROUP" >/dev/null || groupadd "$SFTP_GROUP"
  mkdir -p "$BASE_DIR"
  chown root:root "$BASE_DIR"
  chmod 755 "$BASE_DIR"
}

# Create/repair one SFTP user, set exact key from CSV
provision_user() {
  local user="$1" key_or_path="$2"
  [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] || return 0

  # Resolve public key (string vs path)
  local pubkey=""
  if [[ "$key_or_path" =~ ^ssh-(rsa|ed25519|dss) ]]; then
    pubkey="$key_or_path"
  else
    [[ -f "$key_or_path" ]] || return 0
    strip_crlf_inplace "$key_or_path"
    pubkey="$(cat "$key_or_path")"
  fi

  local user_root="${BASE_DIR}/${user}"
  local user_ssh="${user_root}/.ssh"
  local user_auth="${user_ssh}/authorized_keys"

  # Create or align user quietly, with nologin shell
  local nologin="/sbin/nologin"; [[ -x "$nologin" ]] || nologin="/usr/sbin/nologin"
  if ! id "$user" >/dev/null 2>&1; then
    useradd -g "$SFTP_GROUP" -s "$nologin" -d "$user_root" "$user" >/dev/null 2>&1
  else
    current_group="$(id -gn "$user")"
    current_shell="$(getent passwd "$user" | cut -d: -f7)"
    current_home="$(getent passwd "$user" | cut -d: -f6)"
    args=()
    [[ "$current_group" != "$SFTP_GROUP" ]] && args+=(-g "$SFTP_GROUP")
    [[ "$current_shell" != "$nologin"    ]] && args+=(-s "$nologin")
    [[ "$current_home"  != "$user_root"  ]] && args+=(-d "$user_root")
    if ((${#args[@]})); then
      usermod "${args[@]}" "$user" >/dev/null 2>&1
    fi
  fi

  # Chroot structure + permissions (NO 'uploads' dir)
  mkdir -p "$user_root" "$user_ssh"
  chown root:root "$user_root"; chmod 755 "$user_root"
  chown "$user":"$SFTP_GROUP" "$user_ssh"; chmod 700 "$user_ssh"

  # authorized_keys
  echo "$pubkey" > "$user_auth"
  strip_crlf_inplace "$user_auth"
  chown "$user":"$SFTP_GROUP" "$user_auth"
  chmod 600 "$user_auth"
}

# ---------- Parse args ----------
if [[ $# -ge 1 && "$1" != "-"* && -z "${CSV_FILE}" ]]; then CSV_FILE="$1"; shift || true; fi
while getopts ":c:g:b:p:h" opt; do
  case "$opt" in
    c) CSV_FILE="$OPTARG" ;;
    g) SFTP_GROUP="$OPTARG" ;;
    b) BASE_DIR="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    h|*) usage ;;
  esac
done
[[ -z "$CSV_FILE" ]] && usage
[[ -f "$CSV_FILE" ]] || { echo "CSV not found: $CSV_FILE" >&2; exit 1; }

need_root
strip_crlf_inplace "$CSV_FILE"

# ---------- Ensure packages / base ----------
command -v sshd >/dev/null 2>&1 || install_pkg_if_missing openssh-server
ensure_group_and_basedir
[[ ! -f "${SSHD_CFG}.bak.initial" ]] && cp -a "$SSHD_CFG" "${SSHD_CFG}.bak.initial"

# ---------- Configure sshd for SFTP group ----------
ensure_sshd_chroot_block

# ---------- Process CSV (multi-user) ----------
while IFS= read -r line; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  if [[ "$line" =~ ^[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee][[:space:]]*,[[:space:]]*[Pp][Uu][Bb][Ll][Ii][Cc]_[Kk][Ee][Yy] ]]; then
    continue
  fi
  user="${line%%,*}"
  key="${line#*,}"
  user="$(echo "$user" | xargs)"
  key="$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$user" || -z "$key" ]] && continue
  provision_user "$user" "$key"
done < "$CSV_FILE"

# ---------- Validate & restart sshd ----------
validate_and_restart_sshd
