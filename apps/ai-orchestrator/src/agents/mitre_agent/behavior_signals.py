"""
Keyword, regex, and process-name signatures for behavior detection.

Ported from apps/backend/src/domain/mitre/constants/BehaviorPatterns.constants.ts
— a real, carefully-curated signature library that already existed in this
codebase but was never wired into the live pipeline (confirmed during
Phase 3's audit: dead code, no caller). Reused here rather than invented
from scratch. All lists are lowercase; callers must lowercase the input
text before matching.
"""

from __future__ import annotations

import re

POWERSHELL_PROCESS_NAMES = ("powershell.exe", "powershell_ise.exe", "pwsh.exe", "pwsh")

POWERSHELL_DOWNLOAD_CRADLE_PATTERN = re.compile(
    r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|net\.webclient|start-bitstransfer)",
    re.IGNORECASE,
)
ENCODED_POWERSHELL_PATTERN = re.compile(r"-e(?:nc(?:odedcommand)?)?\s+([a-z0-9+/=]{16,})", re.IGNORECASE)

CREDENTIAL_DUMPING_PROCESS_NAMES = ("procdump.exe", "procdump64.exe", "mimikatz.exe", "pwdump.exe", "gsecdump.exe", "nanodump.exe")
CREDENTIAL_DUMPING_TARGET_PROCESSES = ("lsass.exe", "lsass")
CREDENTIAL_DUMPING_KEYWORDS = (
    "sekurlsa",
    "lsadump",
    "logonpasswords",
    "ntdsutil.exe",
    "reg save hklm\\sam",
    "reg.exe save hklm\\sam",
    "comsvcs.dll",
    "minidump",
)

PERSISTENCE_REGISTRY_PATTERNS = (
    re.compile(r"\\microsoft\\windows\\currentversion\\run\b", re.IGNORECASE),
    re.compile(r"\\microsoft\\windows\\currentversion\\runonce\b", re.IGNORECASE),
    re.compile(r"\\currentcontrolset\\services\\", re.IGNORECASE),
    re.compile(r"\\winlogon\\", re.IGNORECASE),
    re.compile(r"\\image file execution options\\", re.IGNORECASE),
)
PERSISTENCE_KEYWORDS = ("schtasks", "sc.exe create", "sc create", "new-scheduledtask", "root\\subscription", "wmic /namespace:\\\\root\\subscription")
PERSISTENCE_STARTUP_PATH_FRAGMENTS = ("\\startup\\programs\\", "\\start menu\\programs\\startup\\")

DEFENSE_EVASION_KEYWORDS = (
    "set-mppreference",
    "-disablerealtimemonitoring",
    "wevtutil cl",
    "wevtutil.exe cl",
    "clear-eventlog",
    "vssadmin delete shadows",
    "bcdedit /set",
    "-w hidden",
    "-windowstyle hidden",
    "amsiutils",
    "amsi bypass",
    "invoke-obfuscation",
)

C2_SUSPICIOUS_PORTS = (4444, 8080, 8443, 1337, 6666, 6667, 12345, 31337)
C2_KEYWORDS = ("beacon", "cobaltstrike", "cobalt strike", "empire", "meterpreter", "metasploit")
C2_THREAT_INTEL_TAG_KEYWORDS = ("c2", "command-and-control", "botnet", "malware-c2")

DISCOVERY_PROCESS_NAMES = (
    "whoami.exe",
    "hostname.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "ipconfig.exe",
    "arp.exe",
    "netstat.exe",
    "quser.exe",
    "wmic.exe",
)
DISCOVERY_ACCOUNT_KEYWORDS = ("net user", "net group", "net localgroup", "nltest /dclist", "nltest /domain_trusts", "dsquery", "adfind", "query user")
DISCOVERY_SYSTEM_KEYWORDS = ("whoami", "systeminfo", "tasklist", "ipconfig /all", "query process")

LATERAL_MOVEMENT_PROCESS_NAMES = ("psexec.exe", "psexesvc.exe", "winrs.exe", "paexec.exe")
LATERAL_MOVEMENT_KEYWORDS = ("psexec", "wmic /node:", "wmic.exe /node:", "process call create", "invoke-command", "enter-pssession", "\\\\admin$", "\\\\c$")
LATERAL_MOVEMENT_RDP_LOGON_TYPE = "10"
LATERAL_MOVEMENT_LOGON_EVENT_IDS = ("4624", "4648")

EXFILTRATION_ARCHIVE_KEYWORDS = ("7z.exe a ", "rar.exe a ", "7z a ", "rar a ")
EXFILTRATION_TRANSFER_KEYWORDS = ("curl -t", "curl --upload", "invoke-restmethod -method post", "certutil -urlcache", "bitsadmin /transfer")
EXFILTRATION_KNOWN_SERVICE_DOMAINS = ("mega.nz", "dropbox.com", "transfer.sh", "pastebin.com", "anonfiles.com", "wetransfer.com")
EXFILTRATION_MIN_BYTES_OUT = 50 * 1024 * 1024

IMPACT_SHADOW_COPY_KEYWORDS = ("vssadmin delete shadows", "vssadmin.exe delete shadows", "bcdedit /set recoveryenabled no", "wbadmin delete catalog", "cipher /w", "fsutil usn deletejournal")
IMPACT_RANSOM_FILE_EXTENSIONS = (".locked", ".encrypted", ".crypt", ".ransom", ".wcry", ".locky")

BRUTE_FORCE_FAILED_LOGON_EVENT_IDS = ("4625", "4771", "4776")
BRUTE_FORCE_MIN_FAILED_ATTEMPTS = 5
BRUTE_FORCE_HIGH_CONFIDENCE_MULTIPLIER = 2
