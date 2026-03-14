// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package models

type Target struct {
	Host string `toml:"host"`
	Port string `toml:"port,omitempty"`
	User string `toml:"user"`
}

type Packages map[string][]string

type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	Published   string  `json:"published,omitempty"`
}

type Vulnerability struct {
	Package string `json:"package"`
	Version string `json:"version"`
	CVEs    []CVE  `json:"cves"`
}

type TargetResult struct {
	TargetName      string          `json:"-"`
	Host            string          `json:"host"`
	OS              string          `json:"os,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Error           string          `json:"error,omitempty"`
}

type FailedLookup struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

type ScanResult struct {
	Version       string                  `json:"version"`
	ScannedAt     string                  `json:"scannedAt"`
	Targets       map[string]TargetResult `json:"targets"`
	FailedLookups []FailedLookup          `json:"failedLookups,omitempty"`
}
