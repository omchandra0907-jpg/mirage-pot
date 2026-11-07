# mirage-pot

> Adaptive deception SSH honeypot with in-memory virtual filesystem, session-unique canary credentials, and live MITRE ATT&CK telemetry HUD.

![mirage-pot Showcase](assets/demo.gif)

[![CI](https://github.com/omchandra0907-jpg/mirage-pot/actions/workflows/ci.yml/badge.svg)](https://github.com/omchandra0907-jpg/mirage-pot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

> **🌐 Live Interactive Web Demo:** [https://omchandra0907-jpg.github.io/mirage-pot/](https://omchandra0907-jpg.github.io/mirage-pot/)

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Live_Attack_HUD_Sandbox-00E5FF?style=for-the-badge&labelColor=0d1117)](https://omchandra0907-jpg.github.io/mirage-pot/)

---

## Key Capabilities

- **High-Concurrency Async Core**: Built on `asyncssh` and `asyncio`, handling hundreds of simultaneous brute-force bots inside a single lightweight event loop without OS thread overhead.
- **Per-Session In-Memory POSIX VFS**: Each connection receives an isolated `VNode` tree (`/etc`, `/root`, `/tmp`, `/bin`). Attackers can write scripts, create directories, and run commands (`ls`, `cat`, `cd`, `echo >`, `ps aux`) with guaranteed containment and zero host touches.
- **Dynamic Canary Baiting**: When attackers inspect `.env`, `~/.ssh/id_rsa`, or `~/.aws/credentials`, `mirage-pot` generates unique, traceable credentials tagged with the attacker's `session_id`, turning intrusion attempts into active threat intelligence.
- **Safe Network Tool Emulation**: Fake `wget` and `curl` commands record destination C2 URLs and write payload stubs locally without executing outbound network requests.
- **Automated MITRE ATT&CK Mapping**: Every command is parsed via regex/AST rules and mapped directly to MITRE ATT&CK techniques (`T1082`, `T1003`, `T1105`, `T1070`, `T1057`).
- **Interactive Session Replay**: Play back captured bot sessions with true inter-keystroke timing delays at `1x` or `4x` speed using the built-in CLI.

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Detection Trigger Examples |
|---|---|---|
| **T1003** | OS Credential Dumping | `cat /etc/shadow`, `cat /root/.env`, `cat ~/.ssh/id_rsa` |
| **T1105** | Ingress Tool Transfer | `curl http://...`, `wget http://...`, `scp` |
| **T1070** | Indicator Removal on Host | `rm -rf /tmp/*`, `history -c`, `unset HISTFILE` |
| **T1082** | System Information Discovery | `uname -a`, `hostname`, `cat /etc/*release` |
| **T1033** | System Owner/User Discovery | `whoami`, `id`, `users`, `last` |
| **T1057** | Process Discovery | `ps aux`, `top`, `htop`, `pgrep` |
| **T1053** | Scheduled Task/Job | `crontab -l`, `crontab -e` |
| **T1562** | Impair Defenses | `iptables -F`, `ufw disable`, `setenforce 0` |

---

## Quickstart

### Installation
```bash
git clone https://github.com/omchandra0907-jpg/mirage-pot.git
cd mirage-pot
pip install -e .
```

### Zero-Setup Live HUD Showcase
Run the simulated multi-attacker telemetry dashboard immediately without configuring SSH keys or network bindings:
```bash
mirage-pot demo
```

### Replay Captured Bot Sessions
Replay pre-bundled bot intrusion sessions with authentic keystroke timing:
```bash
mirage-pot replay samples/session_01.jsonl --speed 2.0
mirage-pot replay samples/session_02.jsonl --speed 4.0
```

### Run Honeypot Listener
```bash
# Start honeypot on port 2222 with live HUD
mirage-pot listen --port 2222 --hud
```

---

## Running Tests

```bash
pytest
```

---

## License

Distributed under the MIT License. Developed by [omchandra0907-jpg](https://github.com/omchandra0907-jpg).
