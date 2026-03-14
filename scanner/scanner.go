// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cortexsecurity/vulu/config"
	"github.com/cortexsecurity/vulu/cve"
	"github.com/cortexsecurity/vulu/models"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Scanner struct {
	Targets              map[string]models.Target
	Version              string
	SSHKeyPath           string
	KnownHostsPath       string
	SSHTimeout           time.Duration
	CommandTimeout       time.Duration
	MaxConnections       int
	CVERequestsPerSecond int
}

type job struct {
	name   string
	target models.Target
}

type targetScan struct {
	name     string
	host     string
	os       string
	packages models.Packages
	err      string
}

type pkgKey struct {
	name    string
	version string
}

func (s Scanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	if len(s.Targets) == 0 {
		slog.Warn("No targets to scan.")
		return nil, nil
	}

	key, hostKeyCallback, err := s.loadCredentials()
	if err != nil {
		return nil, err
	}

	scans := s.scanTargets(ctx, key, hostKeyCallback)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	cveCache, failed, err := s.lookupCVEs(ctx, scans)
	if err != nil {
		return nil, err
	}

	return s.assembleResult(scans, cveCache, failed), nil
}

func (s Scanner) loadCredentials() (ssh.Signer, ssh.HostKeyCallback, error) {
	keyPath := config.ExpandPath(s.SSHKeyPath)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, nil, err
	}

	hostKeyCallback, err := knownhosts.New(s.KnownHostsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot load known_hosts: %w.", err)
	}

	return key, hostKeyCallback, nil
}

func (s Scanner) scanTargets(ctx context.Context, key ssh.Signer, hostKeyCallback ssh.HostKeyCallback) []targetScan {
	numWorkers := min(s.MaxConnections, len(s.Targets))

	jobs := make(chan job, len(s.Targets))
	results := make(chan targetScan, len(s.Targets))

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			for j := range jobs {
				results <- s.scanTarget(ctx, j.name, j.target, key, hostKeyCallback)
			}
		})
	}

	for name, target := range s.Targets {
		jobs <- job{name: name, target: target}
	}
	close(jobs)

	wg.Wait()
	close(results)

	var scans []targetScan
	for scan := range results {
		if scan.err != "" {
			slog.Warn("Target scan failed.", "name", scan.name, "error", scan.err)
		}
		scans = append(scans, scan)
	}

	return scans
}

func (s Scanner) lookupCVEs(ctx context.Context, scans []targetScan) (map[pkgKey][]models.CVE, []models.FailedLookup, error) {
	allPackages := make(map[pkgKey]bool)
	for _, scan := range scans {
		for pkg, versions := range scan.packages {
			for _, version := range versions {
				allPackages[pkgKey{pkg, version}] = true
			}
		}
	}

	cveCache := make(map[pkgKey][]models.CVE)
	if len(allPackages) == 0 {
		return cveCache, nil, nil
	}

	slog.Info("Checking vulnerabilities.", "packages", len(allPackages))
	client := cve.NewClient(s.CVERequestsPerSecond)
	defer client.Close()

	type cveResult struct {
		key  pkgKey
		cves []models.CVE
	}

	jobs := make(chan pkgKey, len(allPackages))
	results := make(chan cveResult, len(allPackages))
	failures := make(chan pkgKey, len(allPackages))

	var wg sync.WaitGroup
	numWorkers := min(s.CVERequestsPerSecond, len(allPackages))
	for range numWorkers {
		wg.Go(func() {
			for key := range jobs {
				cves, err := client.Search(ctx, key.name, key.version)
				if err != nil {
					slog.Warn("CVE lookup failed.", "package", key.name, "error", err)
					failures <- key
					continue
				}
				if len(cves) > 0 {
					results <- cveResult{key: key, cves: cves}
					slog.Debug("Vulnerabilities found.", "package", key.name, "count", len(cves))
				}
			}
		})
	}

	for key := range allPackages {
		jobs <- key
	}
	close(jobs)

	wg.Wait()
	close(results)
	close(failures)

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	for res := range results {
		cveCache[res.key] = res.cves
	}

	var failed []models.FailedLookup
	for key := range failures {
		failed = append(failed, models.FailedLookup{Package: key.name, Version: key.version})
	}

	if len(failed) > 0 {
		slog.Warn("Some CVE lookups failed.", "failed", len(failed), "total", len(allPackages))
	}

	slog.Info("Vulnerability check complete.")
	return cveCache, failed, nil
}

func (s Scanner) assembleResult(scans []targetScan, cveCache map[pkgKey][]models.CVE, failed []models.FailedLookup) *models.ScanResult {
	result := &models.ScanResult{
		Version:       s.Version,
		ScannedAt:     time.Now().Format("2006-01-02T15:04:05.000"),
		Targets:       make(map[string]models.TargetResult),
		FailedLookups: failed,
	}

	for _, scan := range scans {
		var vulns []models.Vulnerability
		for pkg, versions := range scan.packages {
			for _, version := range versions {
				key := pkgKey{pkg, version}
				if cves, ok := cveCache[key]; ok {
					vulns = append(vulns, models.Vulnerability{
						Package: pkg,
						Version: version,
						CVEs:    cves,
					})
				}
			}
		}
		result.Targets[scan.name] = models.TargetResult{
			TargetName:      scan.name,
			Host:            scan.host,
			OS:              scan.os,
			Vulnerabilities: vulns,
			Error:           scan.err,
		}
	}

	return result
}

func (s Scanner) scanTarget(ctx context.Context, name string, target models.Target, key ssh.Signer, hostKeyCallback ssh.HostKeyCallback) targetScan {
	slog.Info("Scanning target.", "name", name)

	sshClientConfig := &ssh.ClientConfig{
		User: target.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         s.SSHTimeout,
	}

	port := target.Port
	if port == "" {
		port = "22"
	}

	address := net.JoinHostPort(target.Host, port)
	client, err := dialSSH(ctx, address, sshClientConfig)
	if err != nil {
		return targetScan{name: name, host: target.Host, err: "Connection failed: " + err.Error()}
	}
	defer client.Close()

	slog.Debug("Connected.", "host", target.Host)

	osCtx, osCancel := context.WithTimeout(ctx, s.CommandTimeout)
	defer osCancel()

	targetOS := getTargetOS(osCtx, client)
	packages := make(models.Packages)

	pkgCtx, pkgCancel := context.WithTimeout(ctx, s.CommandTimeout)
	defer pkgCancel()

	switch targetOS {
	case "fedora", "opensuse-leap", "centos", "rhel", "rocky":
		output, err := runCommand(pkgCtx, client, `rpm -qa --queryformat "%{NAME} %{VERSION}\n"`)
		if err != nil {
			return targetScan{name: name, host: target.Host, os: targetOS, err: "RPM query failed: " + err.Error()}
		}
		parsePackages(string(output), packages)

	case "debian", "ubuntu":
		output, err := runCommand(pkgCtx, client, `dpkg-query -W -f='${Package} ${Version}\n'`)
		if err != nil {
			return targetScan{name: name, host: target.Host, os: targetOS, err: "DPKG query failed: " + err.Error()}
		}
		parsePackages(string(output), packages)

	default:
		return targetScan{name: name, host: target.Host, os: targetOS, err: "Unsupported OS: " + targetOS}
	}

	slog.Info("Finished scanning.", "name", name)
	return targetScan{name: name, host: target.Host, os: targetOS, packages: packages}
}

func dialSSH(ctx context.Context, address string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
	if err != nil {
		stop()
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !stop() {
		sshConn.Close()
		return nil, ctx.Err()
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func runCommand(ctx context.Context, client *ssh.Client, command string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	stop := context.AfterFunc(ctx, func() {
		session.Close()
	})
	defer stop()

	output, err := session.Output(command)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return output, nil
}

func getTargetOS(ctx context.Context, client *ssh.Client) string {
	output, err := runCommand(ctx, client, "cat /etc/os-release")
	if err != nil {
		slog.Error("Failed to read /etc/os-release.", "error", err)
		return "Unknown"
	}
	return parseOSRelease(string(output))
}

func parseOSRelease(content string) string {
	for line := range strings.Lines(content) {
		trimmed := strings.TrimSpace(line)
		key, value, _ := strings.Cut(trimmed, "=")
		if strings.ToUpper(key) == "ID" {
			return strings.Trim(value, `'"`)
		}
	}
	return "Unknown"
}

func parsePackages(stdout string, packages models.Packages) {
	lines := strings.Lines(stdout)

	for line := range lines {
		trimmed := strings.TrimSpace(line)
		name, version, found := strings.Cut(trimmed, " ")

		if !found {
			continue
		}

		if !slices.Contains(packages[name], version) {
			packages[name] = append(packages[name], version)
		}
	}
}
