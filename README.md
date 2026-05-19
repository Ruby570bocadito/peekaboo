<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=0A66C2&height=100&section=header&text=peekaboo&fontSize=40&fontColor=ffffff&fontAlign=50&fontAlignY=50&animation=fadeIn" alt="header"/>
</p>

<p align="center">
  <strong>Linux Privilege Escalation Auto-Exploiter</strong><br/>
  <em>Single binary. Zero dependencies. Auto-root.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/status-active-green?style=for-the-badge" alt="Status"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/size-2MB-orange?style=for-the-badge" alt="Size"/>
  <img src="https://img.shields.io/badge/deps-zero-9cf?style=for-the-badge" alt="Zero Dependencies"/>
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=Ruby570bocadito&label=Downloads&color=0A66C2&style=flat" alt="downloads"/>
</p>

---

## 🎯 What is peekaboo?

**peekaboo** is an automated Linux privilege escalation tool that scans a target system, identifies misconfigurations, and **automatically exploits them** to gain root access.

It works in **3 phases**: scan → enumerate → exploit. No network calls. No dependencies. Just drop the binary and run.

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   SCAN      │───▶│  ENUMERATE  │───▶│   EXPLOIT   │
│  (read-only)│    │ GTFOBins DB │    │ Auto-root   │
└─────────────┘    └─────────────┘    └─────────────┘
     10+ vectors         60+ bins        safe→danger
```

Built for **CTF competitions**, **pentesting engagements**, and **red team operations**.

---

## ⚡ Features

| Vector | Detection | Exploitation |
|--------|-----------|--------------|
| **SUID Binaries** | Scans 10+ directories for SUID bit | GTFOBins commands for 60+ binaries |
| **Sudo Misconfig** | Parses `sudo -l` output | NOPASSWD + GTFOBins auto-exploit |
| **Writable Cron** | Checks cron dirs + referenced scripts | Reverse shell injection |
| **Docker Breakout** | Detects docker group membership | `docker run -v /:/mnt` escape |
| **Capabilities** | Reads `/proc/self/status` | cap_setuid exploitation |
| **NFS no_root_squash** | Parses `/etc/exports` | Mount + own files as root |
| **Writable PATH** | Checks PATH directories | Binary planting detection |
| **Systemd Services** | Scans `/etc/systemd/system` | Service hijacking |
| **/etc/passwd** | Permission check | Append root user |
| **/etc/shadow** | Permission check | Crack or overwrite hash |

---

## 🚀 Quick Start

### Installation

```bash
# Clone
git clone https://github.com/Ruby570bocadito/peekaboo.git
cd peekaboo

# Build (requires Go 1.26+)
go build -o peekaboo .

# Or download pre-built binary from Releases
```

### Usage

```bash
# Scan only (safe, read-only)
./peekaboo

# Auto-exploit found vectors
./peekaboo --exploit

# Auto-exploit with risk limit
./peekaboo --exploit --risk=medium

# Specific vector only
./peekaboo --vector=suid,sudo

# JSON output for automation
./peekaboo --json

# Quiet mode (exit code: 0=root, 1=fail)
./peekaboo --quiet
```

---

## 🎬 Demo

### Scan Phase

```
 ╔══════════════════════════════════════════╗
 ║     peekaboo — Linux PrivEsc AutoPwn    ║
 ║     ruby570bocadito (c) 2026            ║
 ╚══════════════════════════════════════════╝

  UID: testuser     PID: 1337     Host: target

  [1/3] Scanning system...
  [!] SUID → SUID binary: python3.10 (GTFOBins: true) (/usr/bin/python3.10)
  [.] SUID → SUID binary: find (GTFOBins: true) (/usr/bin/find)
  [!] SUDO → NOPASSWD sudo: /usr/bin/find → find (/usr/bin/find)
  [!] CRON → Writable cron job — inject command (/etc/cron.d/backup)
  [!] FILE → Writable /etc/passwd — inject root user (/etc/passwd)
  [!] FILE → Readable /etc/shadow — crack root hash (/etc/shadow)
  [!] NFS  → NFS export with no_root_squash (/shared *(rw,no_root_squash))

  [2/3] Enumerating vectors...

  ── Findings ──
  [!] SUID → SUID binary: python3.10 (GTFOBins: true) (/usr/bin/python3.10)
  [!] SUDO → NOPASSWD sudo: /usr/bin/find → find (/usr/bin/find)
  [!] CRON → Writable cron job — inject command (/etc/cron.d/backup)
  [!] FILE → Writable /etc/passwd — inject root user (/etc/passwd)

  [3/3] Exploiting... (max risk: MEDIUM)
  [try] SUID python3.10
  [!] ROOT OBTAINED
  Vector: SUID python3.10
  [+] Root shell starting...
```

### All Commands

```bash
./peekaboo                              # Enum only (no exploit)
./peekaboo --exploit                    # Auto-exploit safe vectors first
./peekaboo --exploit --risk=safe        # Only SAFE risks
./peekaboo --exploit --risk=danger      # Everything (including dangerous)
./peekaboo --vector=suid,sudo,cron      # Specific vectors only
./peekaboo --exploit --one-shot         # Stop after first success
./peekaboo --json                       # Machine-readable output
./peekaboo --quiet                      # Exit code only (0=root, 1=fail)
./peekaboo --rooteame ./rooteame.ko     # Load rootkit on success
./peekaboo --stealth                    # Slow scan (evade IDS)
```

---

## 🏗️ Architecture

### Engine Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        peekaboo                              │
├─────────────────────────────────────────────────────────────┤
│  main.go          CLI flags + orchestration                  │
│  universe.go      Types, risk levels, output formatting      │
│  scanner.go       FASE 1 — passive discovery (10+ checkers)  │
│  enumerate.go     FASE 2 — findings → exploit vectors        │
│  exploit.go       FASE 3 — execute vectors (safe→danger)     │
│  gtfobins.go      Offline GTFOBins database (~60 binaries)   │
└─────────────────────────────────────────────────────────────┘
```

### Risk-Based Execution Order

```
SAFE ──▶ LOW ──▶ MEDIUM ──▶ HIGH ──▶ DANGER
 │        │         │         │         │
 │        │         │         │         └─ shadow overwrite
 │        │         │         └─ passwd injection, cron inject
 │        │         └─ cap_sys_ptrace
 │        └─ find SUID, awk sudo
 └─ python SUID spawn shell
```

### File Structure

```
peekaboo/
├── main.go              CLI entry point + orchestration
├── scanner.go           10 vulnerability scanners
├── enumerate.go         Findings → exploit vectors
├── exploit.go           Exploitation engine
├── gtfobins.go          Embedded GTFOBins database
├── universe.go          Types, constants, formatting
├── peekaboo_test.go     Unit tests (9 tests)
│
├── docker/
│   ├── Dockerfile.vulnerable   Target with 10 deliberate flaws
│   ├── Dockerfile.clean        Secure baseline system
│   ├── Dockerfile.edgecases    Edge case scenarios
│   ├── docker-compose.yml      Test network
│   └── test_runner.sh          Automated test runner
│
├── brain/               Development documentation
│   └── SESSION_*.md
│
└── README.md
```

---

## 🧪 Docker Testing

```bash
# Build all test images
cd docker
docker compose build

# Start test network (vulnerable + clean + edgecases)
docker compose up -d

# Run peekaboo on vulnerable target
docker exec peekaboo-vulnerable peekaboo --exploit

# Run on clean system (should find minimal vectors)
docker exec peekaboo-clean peekaboo

# Run edge case scenarios
docker exec peekaboo-edgecases peekaboo --vector=sudo

# Run full test suite
./test_runner.sh
```

---

## 📊 Risk Levels

| Level | Examples | Auto-Exploit? | Filesystem Changes? |
|-------|----------|---------------|---------------------|
| **SAFE** | python SUID → shell | ✅ Yes | No |
| **LOW** | find SUID, awk sudo | ✅ Yes | Minor |
| **MEDIUM** | cap_sys_ptrace | ⚠️ Optional | May trigger alerts |
| **HIGH** | passwd injection, cron inject, docker breakout | ⚠️ Optional | Yes |
| **DANGER** | shadow overwrite, kernel exploits | ❌ Manual only | Yes, may crash |

---

## 📦 GTFOBins Database

**60+ binaries** with exploitation commands, **embedded in the binary**. No network calls at runtime. Works air-gapped.

<details>
<summary><b>Click to see all supported binaries</b></summary>

**Shell binaries (SUID):** python, python2, python3, python3.8-3.13, perl, perl5, php, php5-8.2, ruby, ruby2-3, lua, lua5.3-5.4, node, nodejs, bash, dash, zsh, ksh, fish, sh

**Sudo binaries:** find, vim, vi, less, more, man, awk, gawk, nawk, sed, gdb, nmap, tcpdump, tar, zip, unzip, rsync, scp, socat, env, nice, timeout, stdbuf, watch, make, pip, pip3, npm, gem, git, ssh, docker, lxc, apache2, cpan, ed, ex, ftp, wall, systemctl, journalctl, mysql, psql, sqlite3

</details>

---

## 🗺️ Roadmap

- [ ] Kernel CVE detection module (Dirty Pipe, PwnKit, etc.)
- [ ] GTFOBins auto-update from official repository
- [ ] SSH key detection and credential scanning
- [ ] `--lhost`/`--lport` flags for reverse shell payloads
- [ ] Structured logging with levels (DEBUG, INFO, WARN, ERROR)
- [ ] CSV/HTML report export
- [ ] `--dry-run` mode (predict without executing)
- [ ] Signal handling (Ctrl+C cleanup)
- [ ] Windows privilege escalation support
- [ ] Integration with C2 frameworks (BTY)

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing**, **CTF competitions**, and **educational purposes** only.

- Use only on systems you own or have explicit written permission to test
- Misuse may violate local and international laws
- The author is not responsible for any misuse or damage caused by this tool

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/Ruby570bocadito">Ruby570bocadito</a></sub>
</p>
