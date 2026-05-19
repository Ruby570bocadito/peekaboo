# peekaboo — Linux Privilege Escalation Auto-Exploiter

Single-binary, zero-dependency Go tool that enumerates and automatically exploits
Linux privilege escalation vectors. Built for CTF and real pentesting.

ruby570bocadito © 2026 — MIT License

---

## Quick Demo

```bash
# Build
go build -o peekaboo .

# Scan only (safe, read-only)
./peekaboo

# Auto-exploit (tries vectors automatically)
./peekaboo --exploit

# Auto-exploit + load rooteame rootkit on success
./peekaboo --exploit --rooteame ../rooteame/src/rooteame.ko

# JSON output for CI/CD integration
./peekaboo --json
```

---

## Features

| Category | Vectors | Technique |
|----------|---------|-----------|
| **SUID** | python, perl, php, ruby, lua, node, bash, find, vim, less, awk, sed, gdb, nmap, tcpdump, tar, zip, rsync, socat, git, ssh, more, man, ... | GTFOBins commands |
| **Sudo** | find, awk, vim, less, nmap, tcpdump, tar, zip, rsync, git, ssh, ... | NOPASSWD + GTFOBins |
| **Files** | /etc/passwd, /etc/shadow | Append root user / crack hash |
| **Cron** | /etc/cron.d/*, /var/spool/cron/* | Inject reverse shell |
| **Docker** | docker group membership | `docker run -v /:/mnt` breakout |
| **Capabilities** | cap_sys_ptrace, cap_dac_override | Process injection |
| **NFS** | no_root_squash | Mount + own files |
| **PATH** | Writable directories in PATH | Binary planting |
| **Services** | Writable systemd units | Service hijacking |

## Architecture

```
peekaboo/
├── main.go          CLI flags + engine orchestration
├── universe.go      Types, risk levels, output formatting
├── scanner.go       FASE 1 — passive discovery (10+ checkers)
├── enumerate.go     FASE 2 — findings → exploit vectors
├── exploit.go       FASE 3 — execute vectors (safe→danger)
├── gtfobins.go      Offline GTFOBins database (~60 binaries)
├── go.mod
│
├── docker/
│   ├── Dockerfile.victim     Vulnerable VM (7 deliberate flaws)
│   └── docker-compose.yml    Test environment
│
└── README.md
```

### Engine flow

```
1. SCAN      → filesystem, sudo, cron, docker, caps, PATH
2. ENUM      → match findings against GTFOBins database
3. SORT      → order by risk (SAFE → LOW → MEDIUM → HIGH → DANGER)
4. EXPLOIT   → try each vector until root or exhausted
5. RESULT    → spawn root shell or print top vectors
```

## Commands

```bash
peekaboo                              # Enum only (no exploit)
peekaboo --exploit                    # Auto-exploit safe vectors first
peekaboo --exploit --risk=safe        # Only SAFE risks (Python SUID etc.)
peekaboo --exploit --risk=danger      # Everything (kernel exploits, shadow write)
peekaboo --vector=suid,sudo,cron      # Specific vectors only
peekaboo --exploit --one-shot         # Stop after first success
peekaboo --json                       # Machine-readable output
peekaboo --quiet                      # Exit code only (0=root, 1=fail)
peekaboo --rooteame ./rooteame.ko     # Load rootkit on success
peekaboo --stealth                    # Slow scan (evade IDS)
```

## Docker Test

```bash
# Build vulnerable VM
docker compose -f docker/docker-compose.yml build

# Start target + attacker
docker compose -f docker/docker-compose.yml up -d

# Run peekaboo on the vulnerable VM
docker exec peekaboo-target /tools/peekaboo --exploit

# Manual test
docker exec -it peekaboo-target bash
su user
/tools/peekaboo --exploit
```

## GTFOBins Database

60+ binaries with exploitation commands, embedded in the binary.
No network calls at runtime. Works air-gapped.

Covers: python, perl, php, ruby, lua, node, bash, dash, zsh, ksh, fish,
find, vim, vi, less, more, man, awk, gawk, nawk, sed, gdb, nmap, tcpdump,
tar, zip, unzip, rsync, scp, socat, env, nice, timeout, stdbuf, watch, make,
pip, npm, gem, git, ssh, ed, ex, ftp, wall, systemctl, journalctl, mysql,
psql, sqlite3, apache2, lxc, docker, cpan.

## Risk Levels

| Level | Examples | Safe to auto-exploit? |
|-------|----------|----------------------|
| **SAFE** | python SUID spawn shell | No filesystem modification |
| **LOW** | find SUID, awk sudo | Minor artifacts |
| **MEDIUM** | cap_sys_ptrace | May trigger alerts |
| **HIGH** | passwd injection, cron inject, docker breakout | Modifies system files |
| **DANGER** | shadow overwrite, kernel CVE launcher | May crash or corrupt |

## Stack

| Component | Choice |
|-----------|--------|
| Language | Go 1.26 |
| Dependencies | **Zero** (stdlib only) |
| GTFOBins DB | Embedded in binary |
| Output | Colored text + JSON |
| Binary size | ~3.4 MB (unstripped), ~2 MB stripped |

## Disclaimer

For authorized security testing only. Misuse may violate laws.
