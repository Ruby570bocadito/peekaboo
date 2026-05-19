package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ================================================================
// FASE 1 — Scanner: passivo, no modifica nada
// ================================================================

func scanAll(p *Peekaboo) {
	scanSUID(p)
	scanSudo(p)
	scanCron(p)
	scanPasswd(p)
	scanShadow(p)
	scanDocker(p)
	scanCapabilities(p)
	scanNFS(p)
	scanWritablePath(p)
	scanServices(p)
}

func addFinding(p *Peekaboo, source, target, desc string, risk RiskLevel, exploitable bool) {
	p.Findings = append(p.Findings, Finding{
		Source:      source,
		Target:      target,
		Description: desc,
		Risk:        risk,
		Exploitable: exploitable,
	})
	if !p.Opts.JSON && !p.Opts.Quiet && exploitable {
		p.Print(p.Findings[len(p.Findings)-1])
	}
}

// --- SUID ---
func scanSUID(p *Peekaboo) {
	// Common SUID paths
	paths := []string{
		"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
		"/usr/local/sbin", "/snap/bin", "/opt", "/usr/lib",
	}
	seen := map[string]bool{}

	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || seen[e.Name()] {
				continue
			}
			full := filepath.Join(dir, e.Name())
			info, err := os.Lstat(full)
			if err != nil {
				continue
			}
			// SUID bit set
			if info.Mode()&os.ModeSetuid != 0 && !info.Mode().IsDir() && info.Mode().IsRegular() {
				seen[e.Name()] = true
				bin := e.Name()
				risk := RiskMedium

				_, isGTFO := getCommand(bin)
				isShell := isSuidShellBin(bin)

				if isShell {
					risk = RiskHigh
				} else if isGTFO {
					risk = RiskLow
				}

				addFinding(p, "SUID", full,
					fmt.Sprintf("SUID binary: %s (GTFOBins: %v)", bin, isGTFO || isShell),
					risk, isGTFO || isShell)
			}
		}
	}
}

// --- Sudo ---
func scanSudo(p *Peekaboo) {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}

	// Check sudo -l
	cmd := exec.Command("sudo", "-n", "-l")
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmd2 := exec.Command("sudo", "-l")
		out2, _ := cmd2.CombinedOutput()
		out = out2
	}

	output := string(out)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Matching") || strings.HasPrefix(line, "User") {
			continue
		}

		// Parse: (ALL) NOPASSWD: /usr/bin/find
		// Parse: (root) /usr/bin/awk
		if strings.Contains(line, "NOPASSWD:") || strings.Contains(line, "PASSWD:") ||
			(strings.HasPrefix(line, "(") && strings.Contains(line, "/")) {

			parts := strings.Fields(line)
			for _, part := range parts {
				part = strings.TrimRight(part, ",")
				if strings.HasPrefix(part, "/") {
					bin := filepath.Base(part)
					if cmd, ok := getCommand(bin); ok {
						addFinding(p, "SUDO", part,
							fmt.Sprintf("NOPASSWD sudo: %s → %s", part, strings.SplitN(cmd, " ", 2)[0]),
							RiskHigh, true)
					}
				}
			}
		}
	}

	// Check sudo ALL
	if strings.Contains(output, "(ALL) ALL") || strings.Contains(output, "(root) ALL") ||
		strings.Contains(output, "(ALL : ALL) ALL") {
		addFinding(p, "SUDO", "ALL",
			"Full sudo access — instant root",
			RiskHigh, true)
	}

	// Check if user is in sudo group
	if isInGroup(user, "sudo") || isInGroup(user, "wheel") {
		// Try passwordless sudo
		cmd3 := exec.Command("sudo", "-n", "true")
		if cmd3.Run() == nil {
			addFinding(p, "SUDO", user,
				"User has passwordless sudo",
				RiskHigh, true)
		}
	}
}

func isInGroup(user, group string) bool {
	cmd := exec.Command("groups", user)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == group {
			return true
		}
	}
	return false
}

// --- Cron ---
func scanCron(p *Peekaboo) {
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron/crontabs",
		"/var/spool/cron",
	}

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			// Skip placeholder and hidden files
			if name == ".placeholder" || strings.HasPrefix(name, ".") {
				continue
			}
			// Skip directories
			if e.IsDir() {
				continue
			}
			full := filepath.Join(dir, name)
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			// Check if we can actually write
			if !isWritableByCurrentUser(full) {
				continue
			}
			addFinding(p, "CRON", full,
				"Writable cron job — inject command",
				RiskHigh, true)
		}
	}

	// Check crontab -l for writable scripts referenced
	cmd := exec.Command("crontab", "-l")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "/") {
					info, err := os.Lstat(f)
					if err == nil && info.Mode().Perm()&0200 != 0 && !info.IsDir() {
						if isWritableByCurrentUser(f) {
							addFinding(p, "CRON", f,
								"Crontab references writable file",
								RiskHigh, true)
						}
					}
				}
			}
		}
	}
}

// --- /etc/passwd writable ---
func scanPasswd(p *Peekaboo) {
	info, err := os.Lstat("/etc/passwd")
	if err != nil {
		return
	}
	if info.Mode().Perm()&0200 != 0 {
		addFinding(p, "FILE", "/etc/passwd",
			"Writable /etc/passwd — inject root user",
			RiskHigh, true)
	}
}

// --- /etc/shadow readable/writable ---
func scanShadow(p *Peekaboo) {
	info, err := os.Lstat("/etc/shadow")
	if err != nil {
		return
	}
	if info.Mode().Perm()&0400 != 0 {
		addFinding(p, "FILE", "/etc/shadow",
			"Readable /etc/shadow — crack root hash",
			RiskHigh, true)
	}
	if info.Mode().Perm()&0200 != 0 {
		addFinding(p, "FILE", "/etc/shadow",
			"Writable /etc/shadow — set root password",
			RiskDanger, true)
	}
}

// --- Docker ---
func scanDocker(p *Peekaboo) {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}

	// Check if current user is in docker group
	cmd := exec.Command("groups", user)
	out, err := cmd.Output()
	if err != nil {
		return
	}

	if strings.Contains(string(out), "docker") {
		addFinding(p, "DOCKER", user,
			"User in docker group — container breakout to root",
			RiskHigh, true)
	}

	// Check if docker socket is accessible
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		info, _ := os.Lstat("/var/run/docker.sock")
		if info != nil && info.Mode().Perm()&0060 != 0 {
			// Socket is readable by non-root
		}
	}
}

// --- Capabilities ---
func scanCapabilities(p *Peekaboo) {
	pid := os.Getpid()
	capFile := fmt.Sprintf("/proc/%d/status", pid)

	data, err := os.ReadFile(capFile)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			eff := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			if eff != "0000000000000000" && eff != "0" {
				// Has some effective capabilities
				addFinding(p, "CAPS", eff,
					"Process has non-default capabilities",
					RiskLow, true)
			}
		}
	}

	// Check cap_sys_ptrace specifically via /proc/self/status
	if strings.Contains(string(data), "CapEff:") {
		for _, line := range lines {
			if strings.HasPrefix(line, "CapPrm:") {
				prm := strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
				if strings.Contains(prm, "0000001") || strings.Contains(prm, "0000002") ||
					strings.Contains(prm, "0000004") {
					addFinding(p, "CAPS", "cap_sys_ptrace",
						"SYS_PTRACE capability — can inject into other processes",
						RiskMedium, true)
				}
			}
		}
	}
}

// --- NFS ---
func scanNFS(p *Peekaboo) {
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.Contains(line, "no_root_squash") {
			addFinding(p, "NFS", line,
				"NFS export with no_root_squash — mount and own files as root",
				RiskHigh, true)
		}
	}
}

// --- Writable PATH entries ---
func scanWritablePath(p *Peekaboo) {
	path := os.Getenv("PATH")
	uid := uint32(os.Getuid())
	for _, dir := range strings.Split(path, ":") {
		if dir == "" {
			dir = "."
		}
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0200 != 0 {
			// Only flag if we don't own it
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && stat.Uid != uid {
				addFinding(p, "PATH", dir,
					"Writable directory in PATH (owned by UID "+fmt.Sprintf("%d", stat.Uid)+") — binary planting",
					RiskHigh, true)
			}
		}
	}
}

// isWritableByCurrentUser checks if the current user/group can write to a file
func isWritableByCurrentUser(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	uid := uint32(os.Getuid())
	perm := info.Mode().Perm()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return perm&0002 != 0
	}
	if stat.Uid == uid && perm&0200 != 0 {
		return true
	}
	if perm&0002 != 0 {
		return true
	}
	gid := uint32(os.Getgid())
	if stat.Gid == gid && perm&0020 != 0 {
		return true
	}
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if uint32(g) == stat.Gid && perm&0020 != 0 {
			return true
		}
	}
	return false
}

// --- Writable services ---
func scanServices(p *Peekaboo) {
	dirs := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			info, _ := os.Lstat(full)
			if info == nil {
				continue
			}
			if info.Mode().Perm()&0200 != 0 {
				addFinding(p, "SERVICE", full,
					"Writable systemd service — hijack execution",
					RiskHigh, true)
			}
		}
	}
}
