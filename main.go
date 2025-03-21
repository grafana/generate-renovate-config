package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

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
	DependencyDashboard    bool                `json:"dependencyDashboard"`
	CustomEnvVariables     map[string]string   `json:"customEnvVariables,omitempty"`
	PlatformAutoMerge      bool                `json:"platformAutomerge,omitempty"`
}

type packageRules struct {
	Description       string   `json:"description"`
	MatchBaseBranches []string `json:"matchBaseBranches,omitempty"`
	MatchPackageNames []string `json:"matchPackageNames,omitempty"`
	MatchDatasources  []string `json:"matchDatasources,omitempty"`
	MatchPaths        []string `json:"matchPaths,omitempty"`
	AllowedVersions   string   `json:"allowedVersions,omitempty"`
	GroupName         string   `json:"groupName,omitempty"`
	Enabled           bool     `json:"enabled"`
	AutoMerge         bool     `json:"automerge,omitempty"`
}

type vulnerabilityAlerts struct {
	Enabled bool     `json:"enabled"`
	Labels  []string `json:"labels"`
}

func main() {
	// TODO: Detect.
	mainBranch := "master"
	// TODO: Let user specify.
	rlsBranchPre := "gem-release-"
	app := &cli.App{
		Name:      "generate-renovate-config",
		Usage:     "Generate Renovate configuration for a repository",
		ArgsUsage: "<repository>",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "disable-package",
				Usage: "Package names to disable updates for on the default branch",
			},
			&cli.StringFlag{
				Name:  "disable-packages-reason",
				Usage: "Description for configuration block containing packages disabled by --disable-package",
				Value: "Disable updating of specific dependencies for default branch",
			},
			&cli.StringSliceFlag{
				Name:  "auto-merge-path",
				Usage: "Paths to auto-merge",
			},
			&cli.StringSliceFlag{
				Name:  "group-path",
				Usage: "Paths to group (format: path:group-name)",
			},
		},
		Action: func(cCtx *cli.Context) error {
			if cCtx.Args().Len() != 1 {
				return errors.New("wrong number of arguments")
			}

			repoPath, err := filepath.Abs(cCtx.Args().Get(0))
			if err != nil {
				return fmt.Errorf("failed to get absolute repo path: %w", err)
			}
			if repoPath == "" {
				return fmt.Errorf("empty repo path %q", cCtx.Args().Get(0))
			}

			rlsBranches, err := deduceBranches(repoPath, mainBranch, rlsBranchPre)
			if err != nil {
				return err
			}

			var branchProps []branchProperties
			for _, b := range append([]string{mainBranch}, rlsBranches...) {
				props, err := getBranchProperties(repoPath, b)
				if err != nil {
					return err
				}
				branchProps = append(branchProps, props)
			}

			return renderConfig(repoPath, mainBranch, branchProps, renderOpts{
				disablePackages:       cCtx.StringSlice("disable-package"),
				disablePackagesReason: cCtx.String("disable-packages-reason"),
				autoMergePaths:        cCtx.StringSlice("auto-merge-path"),
				groupPaths:            cCtx.StringSlice("group-path"),
			})
		},
	}
	if err := app.Run(os.Args); err != nil {
		bail(err)
	}
}

// deduceBranches fetches mainBranch and branches matching rlsBranchPre from origin.
// The relevant release branches are returned.
func deduceBranches(repoPath, mainBranch, rlsBranchPre string) ([]string, error) {
	// Make sure the branches are available locally, in case we're under CI.
	refSpec := fmt.Sprintf("refs/heads/%s*:refs/remotes/origin/%s*", rlsBranchPre, rlsBranchPre)
	var b strings.Builder
	cmd := exec.Command("git", "fetch", "origin", mainBranch, refSpec)
	cmd.Dir = repoPath
	cmd.Stderr = &b
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'git fetch origin %s %s': %s", mainBranch, refSpec, b.String())
	}

	cmd = exec.Command("git", "branch", "-r")
	cmd.Dir = repoPath
	b.Reset()
	cmd.Stdout = &b
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'git branch -r': %w", err)
	}

	// Find all releases, sorted.
	// Take the two last minor releases. Iff the previous major is not too old, take also its latest minor.
	reRlsBranch := regexp.MustCompile(fmt.Sprintf(`^origin/%s(\d+)\.(\d+)$`, regexp.QuoteMeta(rlsBranchPre)))
	lines := strings.Split(b.String(), "\n")
	var versions []version
	for _, l := range lines {
		l = strings.TrimSpace(l)
		ms := reRlsBranch.FindStringSubmatch(l)
		if len(ms) == 0 {
			continue
		}

		major, err := strconv.Atoi(ms[1])
		if err != nil {
			panic(fmt.Errorf("major component should be an integer: %w", err))
		}
		minor, err := strconv.Atoi(ms[2])
		if err != nil {
			panic(fmt.Errorf("minor component should be an integer: %w", err))
		}
		branch := strings.TrimPrefix(l, "origin/")
		versions = append(versions, version{major: major, minor: minor, branch: branch})
	}
	// Sort in descending order.
	slices.SortFunc(versions, func(a, b version) int {
		if a.major < b.major {
			return 1
		}
		if a.minor > b.minor {
			return -1
		}

		// Major is the same.
		if a.minor < b.minor {
			return 1
		}
		if a.minor > b.minor {
			return -1
		}

		// They are equal.
		return 0
	})
	if len(versions) == 0 {
		return nil, fmt.Errorf("no release branches could be found")
	}

	rlsBranches := []string{versions[0].branch}
	if len(versions) > 1 {
		rlsBranches = append(rlsBranches, versions[1].branch)
	}

	currentMajor := versions[0].major
	prevMajor := -1
	var prevMajorVer version
	for _, v := range versions {
		if v.major < currentMajor {
			prevMajor = v.major
			prevMajorVer = v
			break
		}
	}
	if prevMajor < 0 {
		return rlsBranches, nil
	}

	// Determine whether previous major is within maintenance window (<= 1 year old),
	// by finding the last tagged release
	cmd = exec.Command("git", "describe", "--tags", "--abbrev=0", "origin/"+prevMajorVer.branch)
	cmd.Dir = repoPath
	b.Reset()
	cmd.Stdout = &b
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'git describe --tags --abbrev=0 origin/%s': %w", prevMajorVer.branch, err)
	}

	tag := strings.TrimSpace(b.String())
	cmd = exec.Command("git", "log", "-1", "--format=%cd", "--date=unix", tag)
	cmd.Dir = repoPath
	b.Reset()
	cmd.Stdout = &b
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'git log': %w", err)
	}

	date := strings.TrimSpace(b.String())
	secondsSinceEpoch, err := strconv.ParseInt(date, 10, 64)
	if err != nil {
		panic(fmt.Errorf("unexpected Git output: %w", err))
	}
	createdAt := time.Unix(secondsSinceEpoch, 0)
	age := time.Since(createdAt)
	// Avg. days in a year: 365.25.
	if age.Seconds() <= (365.25 * 24 * 60 * 60) {
		// OK, this major is still supported.
		rlsBranches = append(rlsBranches, prevMajorVer.branch)
	}

	return rlsBranches, nil
}

type version struct {
	major  int
	minor  int
	branch string
}

type branchProperties struct {
	name      string
	replaced  []string
	goVersion string
}

// getBranchProperties returns properties per branch.
func getBranchProperties(repoPath, branch string) (branchProperties, error) {
	// Switch repo to branch before analyzing go.mod.

	branchProps := branchProperties{name: branch}

	cmd := exec.Command("git", "branch", "--show-current")
	cmd.Dir = repoPath
	var b strings.Builder
	cmd.Stdout = &b
	if err := cmd.Run(); err != nil {
		return branchProps, fmt.Errorf("failed to execute 'git branch --show-current': %w", err)
	}
	origBranch := strings.TrimSpace(b.String())

	var origCommit string
	if origBranch == "" {
		// We're not on a branch, stick with the commit.
		cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
		cmd.Dir = repoPath
		b.Reset()
		cmd.Stdout = &b
		if err := cmd.Run(); err != nil {
			return branchProps, fmt.Errorf("failed to execute 'git rev-parse --short HEAD': %w", err)
		}
		origCommit = strings.TrimSpace(b.String())
	}

	cmd = exec.Command("git", "switch", branch)
	cmd.Dir = repoPath
	b.Reset()
	cmd.Stderr = &b
	if err := cmd.Run(); err != nil {
		errMsg := b.String()
		cmd = exec.Command("git", "branch")
		cmd.Dir = repoPath
		_ = cmd.Run()
		return branchProps, fmt.Errorf("failed to execute 'git switch %s' in %q: %s", branch, repoPath, errMsg)
	}
	defer func() {
		if origBranch != "" {
			cmd = exec.Command("git", "switch", origBranch)
		} else {
			cmd = exec.Command("git", "checkout", origCommit)
		}
		cmd.Dir = repoPath
		_ = cmd.Run()
	}()

	goModPath := filepath.Join(repoPath, "go.mod")
	inputf, err := os.Open(goModPath)
	if err != nil {
		return branchProps, fmt.Errorf("failed to open %q: %w", goModPath, err)
	}
	defer func() {
		_ = inputf.Close()
	}()

	// Create a new scanner to read the file line by line
	scanner := bufio.NewScanner(inputf)
	inReplaceBlock := false

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
					return branchProps, fmt.Errorf("invalid replace directive format: %q", line)
				}
				branchProps.replaced = append(branchProps.replaced, parts[3])
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
			return branchProps, fmt.Errorf("invalid replace directive format: %q", line)
		}
		branchProps.replaced = append(branchProps.replaced, parts[2])
	}

	// Check for errors from the scanner
	if err := scanner.Err(); err != nil {
		return branchProps, fmt.Errorf("failed to read %q: %w", goModPath, err)
	}

	branchProps.goVersion, err = deduceGoVersion(repoPath)
	return branchProps, err
}

var (
	reGoVersion = regexp.MustCompile(`^FROM golang:(\d+\.\d+\.\d+)(?:[^0-9].*)`)
	reVersion   = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	reGroupSpec = regexp.MustCompile(`^([^:]+):([^:]+)$`)
)

func deduceGoVersion(repoPath string) (string, error) {
	// TODO: Don't hard code.
	fpath := filepath.Join(repoPath, "build-image", "Dockerfile")
	file, err := os.Open(fpath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %q: %w", fpath, err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	var goVersion string
	for scanner.Scan() {
		l := scanner.Text()
		ms := reGoVersion.FindStringSubmatch(l)
		if len(ms) == 0 {
			continue
		}
		goVersion = ms[1]
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read file %q: %w", fpath, err)
	}

	if goVersion == "" {
		return "", fmt.Errorf("failed to determine Go version within %q", fpath)
	}
	return goVersion, nil
}

type renderOpts struct {
	disablePackages       []string
	disablePackagesReason string
	autoMergePaths        []string
	groupPaths            []string
}

func renderConfig(repoPath, mainBranch string, branchProps []branchProperties, opts renderOpts) error {
	gitHubDir := filepath.Join(repoPath, ".github")
	if err := os.MkdirAll(gitHubDir, 0o644); err != nil {
		return fmt.Errorf("failed to create %q: %w", gitHubDir, err)
	}

	var rlsBranches []string
	for _, p := range branchProps[1:] {
		rlsBranches = append(rlsBranches, p.name)
	}

	pkgRules := []packageRules{
		{
			Description:       "Disable non-security updates for release branches",
			MatchBaseBranches: rlsBranches,
			MatchPackageNames: []string{"*"},
			Enabled:           false,
		},
		{
			Description:       "Disable updating of replaced dependencies for default branch",
			MatchBaseBranches: []string{mainBranch},
			MatchPackageNames: branchProps[0].replaced,
			Enabled:           false,
		},
		// Pin Go at the current version, since we want to upgrade it manually.
		{
			Description:       "Pin Go at the current version for the default branch",
			MatchBaseBranches: []string{mainBranch},
			MatchDatasources:  []string{"docker", "golang-version"},
			MatchPackageNames: []string{"go", "golang"},
			AllowedVersions:   branchProps[0].goVersion,
			Enabled:           true,
		},
	}

	if len(opts.disablePackages) > 0 {
		pkgRules = append(pkgRules, packageRules{
			Description:       opts.disablePackagesReason,
			MatchBaseBranches: []string{mainBranch},
			MatchPackageNames: opts.disablePackages,
			Enabled:           false,
		})
	}
	if len(opts.autoMergePaths) > 0 {
		pkgRules = append(pkgRules, packageRules{
			Description:       "Auto-merge packages matching paths",
			MatchBaseBranches: []string{mainBranch},
			MatchPaths:        opts.autoMergePaths,
			AutoMerge:         true,
			Enabled:           true,
		})
	}
	if len(opts.groupPaths) > 0 {
		groups := map[string][]string{}
		for _, spec := range opts.groupPaths {
			ms := reGroupSpec.FindStringSubmatch(spec)
			if len(ms) == 0 {
				return fmt.Errorf("invalid group path spec: %q", spec)
			}
			paths := ms[1]
			name := ms[2]
			groups[name] = append(groups[name], paths)
		}
		for name, paths := range groups {
			pkgRules = append(pkgRules, packageRules{
				Description: "Group paths",
				GroupName:   name,
				MatchBaseBranches: []string{mainBranch},
				MatchPaths:  paths,
				Enabled:     true,
			})
		}
	}

	for _, p := range branchProps[1:] {
		ms := reVersion.FindStringSubmatch(p.goVersion)
		major := ms[1]
		minor := ms[2]
		pkgRules = append(pkgRules,
			packageRules{
				Description:       fmt.Sprintf("Disable updating of replaced dependencies for branch %s", p.name),
				MatchBaseBranches: []string{p.name},
				MatchPackageNames: p.replaced,
				Enabled:           false,
			},
			// Pin Go at the current major.minor version, since we only want to upgrade the patch version (for security fixes).
			packageRules{
				Description:       fmt.Sprintf("Pin Go at the current version for branch %s", p.name),
				MatchBaseBranches: []string{p.name},
				MatchDatasources:  []string{"docker", "golang-version"},
				MatchPackageNames: []string{"go", "golang"},
				AllowedVersions:   fmt.Sprintf("<=%s.%s", major, minor),
				Enabled:           true,
			},
		)
	}
	cfg := renovateConfiguration{
		Schema:       "https://docs.renovatebot.com/renovate-schema.json",
		Extends:      []string{"config:recommended"},
		BaseBranches: append([]string{mainBranch}, rlsBranches...),
		PostUpdateOptions: []string{
			"gomodTidy",
			"gomodUpdateImportPaths",
		},
		BranchPrefix: "deps-update/",
		PackageRules: pkgRules,
		VulnerabilityAlerts: vulnerabilityAlerts{
			Enabled: true,
			Labels:  []string{"security-update"},
		},
		OsvVulnerabilityAlerts: true,
		DependencyDashboard:    false,
		CustomEnvVariables: map[string]string{
			"GOPRIVATE": "github.com/grafana",
		},
	}
	if len(opts.autoMergePaths) > 0 {
		cfg.PlatformAutoMerge = true
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
