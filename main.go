// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/subcommands"

	"github.com/cortexsecurity/vulu/config"
	"github.com/cortexsecurity/vulu/subcmds"
)

func main() {
	var showVersion bool
	flag.StringVar(&config.Path, "config", config.Path, "Path to config file.")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit.")

	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&subcmds.ScanCmd{}, "")
	subcommands.Register(&subcmds.DiscoverCmd{}, "")

	flag.Parse()

	if showVersion {
		fmt.Println("vulu", config.Version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	status := subcommands.Execute(ctx)
	stop()
	os.Exit(int(status))
}
