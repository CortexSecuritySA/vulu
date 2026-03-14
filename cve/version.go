// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package cve

import (
	"cmp"
	"log/slog"
	"strconv"
	"strings"
	"unicode"
)

type affectedVersion struct {
	Version         string `json:"version"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	Status          string `json:"status"`
	VersionType     string `json:"versionType"`
}

func compareVersions(a, b string) int {
	a = normalizeVersion(a)
	b = normalizeVersion(b)

	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := max(len(partsA), len(partsB))

	for i := range maxLen {
		partA := "0"
		partB := "0"
		if i < len(partsA) {
			partA = partsA[i]
		}
		if i < len(partsB) {
			partB = partsB[i]
		}

		cmp := compareSegments(partA, partB)
		if cmp != 0 {
			return cmp
		}
	}

	return 0
}

func compareSegments(a, b string) int {
	runsA := splitRuns(a)
	runsB := splitRuns(b)

	maxLen := max(len(runsA), len(runsB))
	for i := range maxLen {
		var ra, rb string
		if i < len(runsA) {
			ra = runsA[i]
		}
		if i < len(runsB) {
			rb = runsB[i]
		}

		numA, errA := strconv.Atoi(ra)
		numB, errB := strconv.Atoi(rb)

		switch {
		case errA == nil && errB == nil:
			if numA != numB {
				return cmp.Compare(numA, numB)
			}
		case errA == nil:
			return 1
		case errB == nil:
			return -1
		default:
			if ra != rb {
				return cmp.Compare(ra, rb)
			}
		}
	}

	return 0
}

func splitRuns(s string) []string {
	var runs []string
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		j := i
		if unicode.IsDigit(runes[i]) {
			for j < len(runes) && unicode.IsDigit(runes[j]) {
				j++
			}
		} else {
			for j < len(runes) && !unicode.IsDigit(runes[j]) {
				j++
			}
		}
		runs = append(runs, string(runes[i:j]))
		i = j
	}
	return runs
}

func normalizeVersion(v string) string {
	if _, after, ok := strings.Cut(v, ":"); ok {
		v = after
	}
	if before, _, ok := strings.Cut(v, "-"); ok {
		v = before
	}
	if before, _, ok := strings.Cut(v, "+"); ok {
		v = before
	}
	return v
}

func isVersionAffected(installed string, affected []affectedVersion) bool {
	if len(affected) == 0 {
		return false
	}

	for _, av := range affected {
		if av.Status != "affected" {
			continue
		}

		if av.Version == "0" && av.LessThan == "" && av.LessThanOrEqual == "" {
			return true
		}

		startVersion := av.Version
		hasStart := startVersion != ""
		hasLessThan := av.LessThan != ""
		hasLessThanOrEqual := av.LessThanOrEqual != ""

		if hasStart && (hasLessThan || hasLessThanOrEqual) {
			if compareVersions(installed, startVersion) < 0 {
				continue
			}
			if hasLessThan && compareVersions(installed, av.LessThan) >= 0 {
				continue
			}
			if hasLessThanOrEqual && compareVersions(installed, av.LessThanOrEqual) > 0 {
				continue
			}
			return true
		}

		if hasStart && !hasLessThan && !hasLessThanOrEqual {
			if compareVersions(installed, startVersion) == 0 {
				return true
			}
			continue
		}

		if hasLessThan {
			slog.Debug("Unbounded version range.", "lessThan", av.LessThan, "installed", installed)
			if compareVersions(installed, av.LessThan) < 0 {
				return true
			}
		}

		if hasLessThanOrEqual {
			slog.Debug("Unbounded version range.", "lessThanOrEqual", av.LessThanOrEqual, "installed", installed)
			if compareVersions(installed, av.LessThanOrEqual) <= 0 {
				return true
			}
		}
	}

	return false
}
