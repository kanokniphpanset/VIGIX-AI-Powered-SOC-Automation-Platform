# Small curated subset of MITRE ATT&CK (Enterprise) techniques, matched by
# keyword against alert text. This is intentionally not exhaustive — swap in
# the full STIX bundle from https://github.com/mitre/cti for production use;
# the matching function below doesn't change, only this table grows.

ATTACK_MATRIX: list[dict] = [
    {
        "technique_id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "keywords": ["phishing", "malicious attachment", "spearphishing", "suspicious email"],
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["powershell", "cmd.exe", "bash -c", "wscript", "cscript", "encoded command"],
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "keywords": ["successful login", "valid credentials", "account logon", "impossible travel"],
    },
    {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["brute force", "multiple failed logon", "password spray", "failed login attempts"],
    },
    {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransomware", "file encryption", "extension changed", "ransom note"],
    },
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": ["c2 beacon", "unusual dns", "outbound connection", "known malicious domain"],
    },
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": ["process injection", "dll injection", "reflective loading", "hollowed process"],
    },
    {
        "technique_id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "keywords": ["scheduled task", "cron job", "at.exe", "schtasks"],
    },
]
