// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package subcmds

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/cortexsecurity/vulu/config"
	"github.com/cortexsecurity/vulu/reporter"
	"github.com/cortexsecurity/vulu/scanner"

	"github.com/google/subcommands"
)

type ScanCmd struct {
	outputDir string
}

func (*ScanCmd) Name() string { return "scan" }

func (*ScanCmd) Synopsis() string { return "Scan packages and check versions." }

func (*ScanCmd) Usage() string {
	return `scan:
	Scans package names and versions on targets defined in config.toml.
`
}

func (p *ScanCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.outputDir, "output", "results", "Directory to write scan results.")
}

func (p *ScanCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	slog.Info("Scan started.", "version", config.Version)

	if err := config.Load(); err != nil {
		slog.Error("Config load failed.", "error", err)
		return subcommands.ExitFailure
	}

	slog.Info("Scanning targets.")

	targets := config.Conf.Targets

	s := scanner.Scanner{
		Targets:              targets,
		Version:              config.Version,
		SSHKeyPath:           config.Conf.Common.SSHKeyPath,
		KnownHostsPath:       config.KnownHostsPath(),
		SSHTimeout:           time.Duration(config.Conf.Common.SSHTimeout) * time.Second,
		CommandTimeout:       time.Duration(config.Conf.Common.CommandTimeout) * time.Second,
		MaxConnections:       config.Conf.Common.MaxConnections,
		CVERequestsPerSecond: config.Conf.Common.CVERequestsPerSecond,
	}

	result, err := s.Scan(ctx)
	if err != nil {
		slog.Error("Scan failed.", "error", err)
		return subcommands.ExitFailure
	}

	if result == nil {
		fmt.Println("No targets to scan.")
		return subcommands.ExitSuccess
	}

	path, err := reporter.WriteResults(result, p.outputDir)
	if err != nil {
		slog.Error("Failed to write results.", "error", err)
		return subcommands.ExitFailure
	}

	var vulnPackages int
	uniqueCVEs := make(map[string]bool)
	for _, target := range result.Targets {
		for _, vuln := range target.Vulnerabilities {
			vulnPackages++
			for _, c := range vuln.CVEs {
				uniqueCVEs[c.ID] = true
			}
		}
	}

	fmt.Println()
	fmt.Printf("Targets:  %d\n", len(result.Targets))
	fmt.Printf("Packages: %d\n", vulnPackages)
	fmt.Printf("CVEs:     %d\n", len(uniqueCVEs))
	if len(result.FailedLookups) > 0 {
		fmt.Printf("Failed:   %d (see report)\n", len(result.FailedLookups))
	}
	fmt.Printf("\n%s\n", path)

	return subcommands.ExitSuccess
}
