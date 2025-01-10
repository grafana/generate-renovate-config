package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
)

type renovateConfiguration struct {
	Schema                 string              `json:"$schema"`
	Extends                []string            `json:"extends"`
	BaseBranches           []string            `json:"baseBranches"`
	PostUpdateOptions      []string            `json:"postUpdateOptions"`
	BranchPrefix           string              `json:"branchPrefix"`
	PackageRules           []packageRules      `json:"packageRules"`
	VulnerabilityAlerts    vulnerabilityAlerts `json:"vulnerabilityAlerts"`
	OsvVulnerabilityAlerts bool                `json:"osvVulnerabilityAlerts"`
}

type packageRules struct {
	Description       string   `json:"description"`
	MatchBaseBranches []string `json:"matchBaseBranches,omitempty"`
	PackagePatterns   []string `json:"packagePatterns,omitempty"`
	MatchPackageNames []string `json:"matchPackageNames,omitempty"`
	MatchDatasources  []string `json:"matchDatasources,omitempty"`
	AllowedVersions   string   `json:"allowedVersions,omitempty"`
	Enabled           bool     `json:"enabled"`
}

type vulnerabilityAlerts struct {
	Enabled bool     `json:"enabled"`
	Labels  []string `json:"labels"`
}

func main() {
	app := &cli.App{
		Name:      "generate-renovate-config",
		Usage:     "Generate Renovate configuration for a repository",
		ArgsUsage: "<repository>",
		Action: func(cCtx *cli.Context) error {
			if cCtx.Args().Len() != 1 {
				return errors.New("wrong number of arguments")
			}

			repoPath := cCtx.Args().Get(0)
			replaced, err := getReplaced(repoPath)
			if err != nil {
				return err
			}
			return renderConfig(replaced, repoPath)
		},
	}
	if err := app.Run(os.Args); err != nil {
		bail(err)
	}
}

func getReplaced(repoPath string) ([]string, error) {
	goModPath := filepath.Join(repoPath, "go.mod")
	inputf, err := os.Open(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %q: %w", goModPath, err)
	}
	defer func() {
		_ = inputf.Close()
	}()

	// Create a new scanner to read the file line by line
	scanner := bufio.NewScanner(inputf)
	inReplaceBlock := false

	var replaced []string
	// Iterate over each line in the file
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !inReplaceBlock {
			if strings.HasPrefix(line, "replace (") {
				// Start of a replace block.
				inReplaceBlock = true
				continue
			}

			if strings.HasPrefix(line, "replace ") {
				// A single-line replace directive.
				parts := strings.Fields(line)
				if len(parts) < 5 {
					return nil, fmt.Errorf("invalid replace directive format: %q", line)
				}
				replaced = append(replaced, parts[3])
			}

			continue
		}

		// We're inside a replace directive block.

		if line == ")" {
			inReplaceBlock = false
			continue
		}

		// Split the line into parts
		parts := strings.Fields(line)
		if len(parts) < 4 {
			return nil, fmt.Errorf("invalid replace directive format: %q", line)
		}
		replaced = append(replaced, parts[2])
	}

	// Check for errors from the scanner
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", goModPath, err)
	}

	return replaced, nil
}

func renderConfig(replaced []string, repoPath string) error {
	gitHubDir := filepath.Join(repoPath, ".github")
	if err := os.MkdirAll(gitHubDir, 0o644); err != nil {
		return fmt.Errorf("failed to create %q: %w", gitHubDir, err)
	}

	// TODO: Let user specify.
	rlsBranches := []string{"gem-release-2.15", "gem-release-2.14"}
	cfg := renovateConfiguration{
		Schema:  "https://docs.renovatebot.com/renovate-schema.json",
		Extends: []string{"config:base"},
		// TODO: Detect.
		BaseBranches: append([]string{"master"}, rlsBranches...),
		PostUpdateOptions: []string{
			"gomodTidy",
			"gomodUpdateImportPaths",
		},
		BranchPrefix: "deps-update/",
		PackageRules: []packageRules{
			{
				Description:       "Disable non-security updates for release branches",
				MatchBaseBranches: rlsBranches,
				PackagePatterns:   []string{"*"},
				Enabled:           false,
			},
			{
				Description:       "Disable updating of replaced dependencies",
				MatchPackageNames: replaced,
				Enabled:           false,
			},
			// Pin Go at the current version, since we want to upgrade it manually.
			// Remember to keep this in sync when upgrading our Go version!
			{
				Description:       "Pin Go at the current version for the default branch",
				MatchDatasources:  []string{"docker", "golang-version"},
				MatchPackageNames: []string{"go", "golang"},
				// TODO: Don't hard code.
				AllowedVersions: "<=1.23.2",
			},
			{
				Description:       fmt.Sprintf("Pin Go at the current version for branch %s", rlsBranches[0]),
				MatchBaseBranches: []string{rlsBranches[0]},
				MatchDatasources:  []string{"docker", "golang-version"},
				MatchPackageNames: []string{"go", "golang"},
				// TODO: Don't hard code.
				AllowedVersions: "<=1.23.2",
			},
			{
				Description:       fmt.Sprintf("Pin Go at the current version for branch %s", rlsBranches[1]),
				MatchBaseBranches: []string{rlsBranches[1]},
				MatchDatasources:  []string{"docker", "golang-version"},
				MatchPackageNames: []string{"go", "golang"},
				// TODO: Don't hard code.
				AllowedVersions: "<=1.22.10",
			},
		},
		VulnerabilityAlerts: vulnerabilityAlerts{
			Enabled: true,
			Labels:  []string{"security-update"},
		},
		OsvVulnerabilityAlerts: true,
	}

	outputPath := filepath.Join(gitHubDir, "renovate.json")
	return writeJSON(cfg, outputPath)
}

func writeJSON(cfg renovateConfiguration, outputPath string) (err error) {
	outf, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create %q: %w", outputPath, err)
	}
	defer func() {
		if fErr := outf.Close(); fErr != nil && err == nil {
			err = fmt.Errorf("failed to write %q: %w", outputPath, err)
		}
	}()

	enc := json.NewEncoder(outf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("failed to generate JSON: %w", err)
	}
	return nil
}

func bail(err error) {
	slog.Error(err.Error())
	os.Exit(1)
}
