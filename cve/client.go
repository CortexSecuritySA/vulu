// SPDX-License-Identifier: GPL-3.0-only.
// SPDX-FileCopyrightText: 2026 Cortex Security S.A.
//
// This software is licensed under GPL v3.0 license.
// See LICENSE file at the root of the project.

package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cortexsecurity/vulu/models"
)

const defaultBaseURL = "https://vulnerability.circl.lu/api"

type Client struct {
	http    *http.Client
	ticker  *time.Ticker
	baseURL string
}

func NewClient(requestsPerSecond int) *Client {
	interval := time.Second / time.Duration(requestsPerSecond)
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		ticker:  time.NewTicker(interval),
		baseURL: defaultBaseURL,
	}
}

func (c *Client) Close() {
	c.ticker.Stop()
}

const (
	perPage  = 100
	maxPages = 50
)

func (c *Client) Search(ctx context.Context, product, installedVersion string) ([]models.CVE, error) {
	var cves []models.CVE
	seen := make(map[string]bool)

	for page := 1; page <= maxPages; page++ {
		records, err := c.fetchPage(ctx, product, page)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			break
		}

		for _, rec := range records {
			cveID := rec.CVEMetadata.CVEID
			if cveID == "" || seen[cveID] {
				continue
			}

			var versions []affectedVersion
			for _, aff := range rec.Containers.CNA.Affected {
				if !strings.EqualFold(aff.Product, product) {
					continue
				}
				versions = append(versions, aff.Versions...)
			}

			if !isVersionAffected(installedVersion, versions) {
				continue
			}

			seen[cveID] = true
			cves = append(cves, extractCVE(rec))
		}

		if len(records) < perPage {
			break
		}
	}

	return cves, nil
}

const maxRetries = 3

func (c *Client) fetchPage(ctx context.Context, product string, page int) ([]cveRecord, error) {
	endpoint := fmt.Sprintf("%s/vulnerability/?product=%s&per_page=%d&page=%d",
		c.baseURL, url.QueryEscape(product), perPage, page)

	for attempt := range maxRetries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ticker.C:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			wait := retryAfter(resp)
			slog.Warn("Rate limited, retrying.", "product", product, "attempt", attempt+1, "wait", wait)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API error: %s.", resp.Status)
		}

		var records []cveRecord
		if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
			return nil, err
		}

		return records, nil
	}

	return nil, fmt.Errorf("API rate limited after %d retries: %s.", maxRetries, product)
}

func retryAfter(resp *http.Response) time.Duration {
	if s := resp.Header.Get("Retry-After"); s != "" {
		if seconds, err := strconv.Atoi(s); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return 5 * time.Second
}

func extractCVE(rec cveRecord) models.CVE {
	cve := models.CVE{
		ID:        rec.CVEMetadata.CVEID,
		Published: rec.CVEMetadata.DatePublished,
	}

	for _, d := range rec.Containers.CNA.Descriptions {
		if d.Lang == "en" {
			cve.Description = d.Value
			break
		}
	}
	if cve.Description == "" && len(rec.Containers.CNA.Descriptions) > 0 {
		cve.Description = rec.Containers.CNA.Descriptions[0].Value
	}

	cve.CVSS, cve.Severity = extractCVSS(rec.Containers.CNA.Metrics)
	if cve.CVSS == 0 {
		for _, adp := range rec.Containers.ADP {
			cve.CVSS, cve.Severity = extractCVSS(adp.Metrics)
			if cve.CVSS > 0 {
				break
			}
		}
	}

	return cve
}

func extractCVSS(metrics []metric) (float64, string) {
	var score float64
	var severity string
	var cvssVersion int

	for _, m := range metrics {
		switch {
		case m.CVSSV40.BaseScore > 0 && cvssVersion < 40:
			score = m.CVSSV40.BaseScore
			severity = m.CVSSV40.BaseSeverity
			cvssVersion = 40
		case m.CVSSV31.BaseScore > 0 && cvssVersion < 31:
			score = m.CVSSV31.BaseScore
			severity = m.CVSSV31.BaseSeverity
			cvssVersion = 31
		case m.CVSSV30.BaseScore > 0 && cvssVersion < 30:
			score = m.CVSSV30.BaseScore
			severity = m.CVSSV30.BaseSeverity
			cvssVersion = 30
		case m.CVSSV20.BaseScore > 0 && cvssVersion < 20:
			score = m.CVSSV20.BaseScore
			severity = cvssV2Severity(m.CVSSV20.BaseScore)
			cvssVersion = 20
		}
	}

	return score, severity
}

type cveRecord struct {
	CVEMetadata cveMetadata `json:"cveMetadata"`
	Containers  containers  `json:"containers"`
}

type cveMetadata struct {
	CVEID         string `json:"cveId"`
	DatePublished string `json:"datePublished"`
}

type containers struct {
	CNA cnaContainer   `json:"cna"`
	ADP []adpContainer `json:"adp"`
}

type adpContainer struct {
	Metrics []metric `json:"metrics"`
}

type cnaContainer struct {
	Affected     []affected    `json:"affected"`
	Descriptions []description `json:"descriptions"`
	Metrics      []metric      `json:"metrics"`
}

type affected struct {
	Product  string            `json:"product"`
	Versions []affectedVersion `json:"versions"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metric struct {
	CVSSV40 cvssData   `json:"cvssV4_0"`
	CVSSV31 cvssData   `json:"cvssV3_1"`
	CVSSV30 cvssData   `json:"cvssV3_0"`
	CVSSV20 cvssV2Data `json:"cvssV2_0"`
}

type cvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cvssV2Data struct {
	BaseScore float64 `json:"baseScore"`
}

func cvssV2Severity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
