// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package reporter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cortexsecurity/vulu/models"
)

func WriteResults(scanResult *models.ScanResult, outputDir string) (string, error) {
	data, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		return "", fmt.Errorf("Failed to marshal results: %w.", err)
	}

	if err := os.Mkdir(outputDir, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("Failed to create results directory: %w.", err)
	}

	timestamp := strings.ReplaceAll(scanResult.ScannedAt, ":", "-")
	filename := timestamp + "-packages.json"
	path := filepath.Join(outputDir, filename)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("Failed to write results file: %w.", err)
	}

	return path, nil
}
