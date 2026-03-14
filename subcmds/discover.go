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
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cortexsecurity/vulu/config"
	"github.com/cortexsecurity/vulu/models"

	"github.com/google/subcommands"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	tcpDialTimeout     = 1 * time.Second
	maxDiscoverWorkers = 100
)

type DiscoverCmd struct {
	network    string
	user       string
	port       string
	acceptKeys bool
}

func (*DiscoverCmd) Name() string { return "discover" }

func (*DiscoverCmd) Synopsis() string { return "Discover targets in a network range." }

func (*DiscoverCmd) Usage() string {
	return `discover --network <CIDR> --user <user> [--port <port>]:
	Discovers targets in the specified network range and adds them to config.toml.
`
}

func (d *DiscoverCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.network, "network", "", "Network range in CIDR format (example: 192.168.1.0/24).")
	f.StringVar(&d.user, "user", "", "SSH username.")
	f.StringVar(&d.port, "port", "22", "SSH port.")
	f.BoolVar(&d.acceptKeys, "accept-keys", false, "Accept host keys without prompting.")
}

func (d *DiscoverCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if d.network == "" || d.user == "" {
		slog.Error("--network and --user arguments are required.")
		return subcommands.ExitFailure
	}

	if err := config.Load(); err != nil {
		slog.Error("Config load failed.", "error", err)
		return subcommands.ExitFailure
	}

	keyPath := config.ExpandPath(config.Conf.Common.SSHKeyPath)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		slog.Error("Failed to read SSH key.", "error", err)
		return subcommands.ExitFailure
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		slog.Error("Failed to parse SSH key.", "error", err)
		return subcommands.ExitFailure
	}

	ips, err := parseNetwork(d.network)
	if err != nil {
		slog.Error("Failed to parse network.", "error", err)
		return subcommands.ExitFailure
	}

	slog.Info("Starting discovery.", "network", d.network, "hosts", len(ips))

	existingIPs := make(map[string]bool)
	usedNames := make(map[string]bool)
	for name, target := range config.Conf.Targets {
		existingIPs[target.Host] = true
		usedNames[name] = true
	}

	discovered := discoverHosts(ctx, ips, d.user, d.port, key, config.Conf.Common.SSHTimeout)

	var newHosts []discoveredHost
	var newNames []string
	for _, host := range discovered {
		if existingIPs[host.target.Host] {
			slog.Debug("Target already exists, skipping.", "host", host.target.Host)
			continue
		}
		newHosts = append(newHosts, host)
		newNames = append(newNames, generateUniqueName(host.target.Host, usedNames))
	}

	if len(newHosts) == 0 {
		slog.Info("No new targets discovered.")
		return subcommands.ExitSuccess
	}

	fmt.Printf("\nDiscovered %d new hosts:\n", len(newHosts))
	for _, host := range newHosts {
		fmt.Printf("  %s %s %s\n", host.address, host.hostKey.Type(), ssh.FingerprintSHA256(host.hostKey))
	}
	fmt.Println()

	if !d.acceptKeys {
		fmt.Print("Add these host keys to known_hosts? [y/N]: ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			slog.Info("Host keys not accepted, aborting.")
			return subcommands.ExitSuccess
		}
	}

	knownHostsPath := config.KnownHostsPath()
	if err := writeKnownHosts(knownHostsPath, newHosts); err != nil {
		slog.Error("Cannot write known_hosts.", "error", err)
		return subcommands.ExitFailure
	}

	var newTargets []models.Target
	for _, host := range newHosts {
		newTargets = append(newTargets, host.target)
	}

	if err := config.AppendTargets(newNames, newTargets); err != nil {
		slog.Error("Cannot add targets to config.", "error", err)
		return subcommands.ExitFailure
	}

	slog.Info("Discovery complete.", "new_targets", len(newTargets))
	return subcommands.ExitSuccess
}

const (
	minPrefixLen  = 16
	warnPrefixLen = 20
)

func parseNetwork(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("IPv6 is not supported. Use IPv4 CIDR range.")
	}

	if prefix.Bits() < minPrefixLen {
		return nil, fmt.Errorf("Prefix /%d too large, minimum is /%d.", prefix.Bits(), minPrefixLen)
	}

	if prefix.Bits() < warnPrefixLen {
		slog.Warn("Network range is large.", "cidr", cidr, "prefix", prefix.Bits())
	}

	var ips []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

type discoveredHost struct {
	target  models.Target
	hostKey ssh.PublicKey
	address string
}

type discoverJob struct {
	ip   netip.Addr
	user string
	port string
}

func discoverHosts(ctx context.Context, ips []netip.Addr, user, port string, key ssh.Signer, timeout int) []discoveredHost {
	numWorkers := min(maxDiscoverWorkers, len(ips))

	jobs := make(chan discoverJob, len(ips))
	results := make(chan *discoveredHost, len(ips))

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			for j := range jobs {
				results <- tryConnect(ctx, j, key, timeout)
			}
		})
	}

	for _, ip := range ips {
		jobs <- discoverJob{ip: ip, user: user, port: port}
	}
	close(jobs)

	wg.Wait()
	close(results)

	var discovered []discoveredHost
	for result := range results {
		if result != nil {
			discovered = append(discovered, *result)
		}
	}

	return discovered
}

func tryConnect(ctx context.Context, j discoverJob, key ssh.Signer, timeout int) *discoveredHost {
	host := j.ip.String()
	address := net.JoinHostPort(host, j.port)

	dialer := net.Dialer{Timeout: tcpDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		slog.Debug("Host unreachable.", "host", host)
		return nil
	}

	var hostKey ssh.PublicKey
	sshConfig := &ssh.ClientConfig{
		User: j.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			hostKey = k
			return nil
		},
		Timeout: time.Duration(timeout) * time.Second,
	}

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		stop()
		conn.Close()
		slog.Debug("SSH authentication failed.", "host", host, "error", err)
		return nil
	}
	if !stop() {
		c.Close()
		return nil
	}

	client := ssh.NewClient(c, chans, reqs)
	client.Close()

	slog.Info("Discovered host.", "host", host)

	return &discoveredHost{
		target:  models.Target{Host: host, Port: j.port, User: j.user},
		hostKey: hostKey,
		address: address,
	}
}

func generateUniqueName(ip string, usedNames map[string]bool) string {
	baseName := generateBaseName(ip)
	name := baseName
	counter := 2

	for usedNames[name] {
		name = fmt.Sprintf("%s-%d", baseName, counter)
		counter++
	}

	usedNames[name] = true
	return name
}

func generateBaseName(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		name = strings.Split(name, ".")[0]
		if sanitized := sanitizeName(name); sanitized != "" {
			return sanitized
		}
	}

	return "host-" + strings.NewReplacer(".", "-", ":", "-").Replace(ip)
}

func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, strings.ToLower(name))
}

func writeKnownHosts(path string, hosts []discoveredHost) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, host := range hosts {
		line := knownhosts.Line([]string{host.address}, host.hostKey)
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}

	return nil
}
