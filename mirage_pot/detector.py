"""MITRE ATT&CK Telemetry and Command Classification Engine."""

import re
from dataclasses import dataclass
from typing import Optional, List, Tuple

@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL

RULES: List[Tuple[re.Pattern, MitreTechnique]] = [
    # Credential Access
    (re.compile(r"\bcat\s+.*(/etc/shadow|/etc/passwd|\.env|\.aws/credentials|id_rsa)", re.I),
     MitreTechnique("T1003", "OS Credential Dumping", "Credential Access", "CRITICAL")),
    
    # Ingress Tool Transfer
    (re.compile(r"\b(curl|wget|nc\s+-l|fetch|tftp|scp)\b", re.I),
     MitreTechnique("T1105", "Ingress Tool Transfer", "Command and Control", "HIGH")),

    # Defense Evasion / Indicator Removal
    (re.compile(r"\b(rm\s+-(rf|fr)|shred|history\s+-c|unset\s+HISTFILE)\b", re.I),
     MitreTechnique("T1070", "Indicator Removal on Host", "Defense Evasion", "HIGH")),
    (re.compile(r"\b(iptables\s+-F|ufw\s+disable|setenforce\s+0)\b", re.I),
     MitreTechnique("T1562", "Impair Defenses", "Defense Evasion", "CRITICAL")),

    # Persistence / Account Manipulation
    (re.compile(r"(authorized_keys|useradd|usermod|addgroup)", re.I),
     MitreTechnique("T1098", "Account Manipulation", "Persistence", "HIGH")),
    (re.compile(r"\b(crontab|/etc/cron)\b", re.I),
     MitreTechnique("T1053", "Scheduled Task/Job", "Persistence", "MEDIUM")),

    # Discovery
    (re.compile(r"\b(whoami|id|groups|users|last)\b", re.I),
     MitreTechnique("T1033", "System Owner/User Discovery", "Discovery", "LOW")),
    (re.compile(r"\b(uname|hostname|lsb_release|cat\s+/proc/version|cat\s+/etc/\*release)\b", re.I),
     MitreTechnique("T1082", "System Information Discovery", "Discovery", "LOW")),
    (re.compile(r"\b(ps\s+|top|htop|pstree|pgrep)\b", re.I),
     MitreTechnique("T1057", "Process Discovery", "Discovery", "LOW")),
    (re.compile(r"\b(netstat|ss\s+|ifconfig|ip\s+a|arp|route)\b", re.I),
     MitreTechnique("T1049", "Network Service Discovery", "Discovery", "LOW")),
    (re.compile(r"\b(find|locate|ls\s+-(la|lR|R))\b", re.I),
     MitreTechnique("T1083", "File and Directory Discovery", "Discovery", "LOW")),
    
    # Execution
    (re.compile(r"\b(bash|sh|zsh|python|perl|ruby)\s+(-c|\S+\.sh|\S+\.py)?", re.I),
     MitreTechnique("T1059", "Command & Scripting Interpreter", "Execution", "MEDIUM")),
]

def classify_command(cmd: str) -> Optional[MitreTechnique]:
    """Matches command against signature table and returns matching MITRE ATT&CK technique."""
    clean_cmd = cmd.strip()
    for pattern, tech in RULES:
        if pattern.search(clean_cmd):
            return tech
    return None

# Rule mapping: T1082 System Information Discovery

# Rule mapping: T1003 OS Credential Dumping

# Rule mapping: T1105 Ingress Tool Transfer
