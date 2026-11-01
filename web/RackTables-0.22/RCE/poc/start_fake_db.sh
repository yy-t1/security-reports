#!/bin/bash
# Start the fake MySQL that "accepts any username/password", listening on 0.0.0.0:3308
pkill -f fake_mysql_any.py 2>/dev/null
rm -f /tmp/fake_mysql.log
nohup python3 /mnt/e/zcode/data/CVE/fake_mysql_any.py 3308 >/tmp/fake_mysql.log 2>&1 &
disown
sleep 1.5
echo "[*] log:"
cat /tmp/fake_mysql.log
echo "[*] listening:"
ss -lntp 2>/dev/null | grep 3308 || netstat -lntp 2>/dev/null | grep 3308
echo "[*] attacker IP: $(hostname -I | awk '{print $1}')"