// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/cortexsecurity/vulu/models"
)

const Version = "1.0"

var Path = "config.toml"

type CommonOpts struct {
	SSHKeyPath           string `toml:"ssh_key_path"`
	KnownHostsPath       string `toml:"known_hosts_path"`
	SSHTimeout           int    `toml:"ssh_timeout_seconds"`
	CommandTimeout       int    `toml:"command_timeout_seconds"`
	MaxConnections       int    `toml:"max_connections"`
	CVERequestsPerSecond int    `toml:"cve_requests_per_second"`
}

func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return os.ExpandEnv(home + path[1:])
		}
	}
	return os.ExpandEnv(path)
}

func KnownHostsPath() string {
	if Conf.Common.KnownHostsPath != "" {
		return ExpandPath(Conf.Common.KnownHostsPath)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/.ssh/known_hosts"
	}
	return ""
}

type Config struct {
	Common  CommonOpts
	Targets map[string]models.Target
}

const (
	defaultSSHTimeout           = 30
	defaultCommandTimeout       = 60
	defaultMaxConnections       = 10
	defaultCVERequestsPerSecond = 50
)

var Conf Config

func Load() error {
	if _, err := toml.DecodeFile(Path, &Conf); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("Config file not found. Copy config.example.toml to %s and configure your targets.", Path)
		}
		return fmt.Errorf("Config decode failed: %w.", err)
	}

	if Conf.Common.SSHKeyPath == "" {
		return fmt.Errorf("ssh_key_path is required.")
	}

	applyIntDefault(&Conf.Common.SSHTimeout, "ssh_timeout_seconds", defaultSSHTimeout)
	applyIntDefault(&Conf.Common.CommandTimeout, "command_timeout_seconds", defaultCommandTimeout)
	applyIntDefault(&Conf.Common.MaxConnections, "max_connections", defaultMaxConnections)
	applyIntDefault(&Conf.Common.CVERequestsPerSecond, "cve_requests_per_second", defaultCVERequestsPerSecond)

	return nil
}

func applyIntDefault(field *int, name string, defaultVal int) {
	if *field == 0 {
		slog.Info("Using default value.", "field", name, "value", defaultVal)
		*field = defaultVal
	} else if *field < 0 {
		slog.Warn("Invalid value, using default.", "field", name, "got", *field, "default", defaultVal)
		*field = defaultVal
	}
}

func AppendTargets(names []string, targets []models.Target) error {
	f, err := os.OpenFile(Path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for i, target := range targets {
		section := fmt.Sprintf("\n[targets.%s]\nhost = %q\nport = %q\nuser = %q\n",
			names[i], target.Host, target.Port, target.User)
		if _, err := f.WriteString(section); err != nil {
			return err
		}
	}

	return nil
}
