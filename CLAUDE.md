# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go CLI tool that generates Renovate configuration files for Go repositories. The tool analyzes a target repository's git branches, go.mod files, and Dockerfiles to create customized Renovate rules that:
- Handle multiple release branches with different dependency update strategies
- Disable updates for dependencies pinned via `replace` directives in go.mod
- Pin Go versions based on what's currently in use
- Support auto-merging and grouping of specific paths

## Development Commands

**Build the binary:**
```bash
go build -o generate-renovate-config main.go
```

**Run the tool:**
```bash
go run main.go <path-to-repository>
```

**Run with options:**
```bash
go run main.go <path-to-repository> \
  --disable-package github.com/foo/bar \
  --auto-merge-path "stacks/*/go.mod" \
  --group-path "stacks/dev-*:dev-stacks"
```

**Lint the code:**
```bash
golangci-lint run
```

**Format the code:**
```bash
golangci-lint run --fix
```

## Code Architecture

### Single-File Structure
The entire application is contained in main.go (~560 lines). Key components:

**Core Data Types:**
- `renovateConfiguration`: Top-level Renovate config structure (lines 22-34)
- `packageRules`: Individual Renovate package rules (lines 36-46)
- `branchProperties`: Properties extracted from each branch (lines 249-253)

**Main Flow (main function, lines 53-119):**
1. Parse CLI arguments using urfave/cli/v3
2. Call `deduceBranches()` to find active release branches
3. Call `getBranchProperties()` for each branch to extract replaced packages and Go version
4. Call `renderConfig()` to generate and write the final renovate.json

**Branch Detection (deduceBranches, lines 121-241):**
- Fetches branches matching pattern `gem-release-X.Y` from origin
- Returns the 2 most recent minor releases, plus the latest from the previous major if it's within 1 year
- Uses git commands: `git fetch`, `git branch -r`, `git describe`, `git log`

**Property Extraction (getBranchProperties, lines 255-335):**
- Switches to the target branch using `switchToBranch()`
- Parses go.mod to find all `replace` directives (both single-line and block format)
- Calls `deduceGoVersion()` to extract Go version from build-image/Dockerfile
- Switches back to original branch

**Go Version Detection (deduceGoVersion, lines 378-407):**
- Hardcoded to look in `build-image/Dockerfile`
- Uses regex to match `FROM golang:X.Y.Z` lines

**Config Generation (renderConfig, lines 416-538):**
- Creates package rules for:
  - Disabling non-security updates on release branches
  - Disabling replaced dependencies
  - Pinning Go versions (exact version for main branch, major.minor for release branches)
  - Custom disable/auto-merge/grouping based on CLI flags
- Writes to `.github/renovate.json`

### Key Patterns

**Branch Analysis Pattern:**
The tool switches between git branches to analyze each branch's dependencies independently. This is necessary because different release branches may have different `replace` directives and Go versions.

**Hardcoded Assumptions:**
- Main branch: "master" (line 55, TODO to detect)
- Release branch prefix: "gem-release-" (line 57, TODO to make configurable)
- Go version source: "build-image/Dockerfile" (line 380, TODO to remove hardcoding)
- GOPRIVATE setting: "github.com/grafana" (line 529)

**Group Path Format:**
The `--group-path` flag expects format "path:group-name" (e.g., "stacks/dev-*:dev-stacks"), parsed by regex at line 375.

## Linting Configuration

The project uses golangci-lint with extensive linters enabled (see .golangci.yml):
- Formatters: gofumpt with extra rules, goimports with local prefix
- Key linters: depguard, errorlint, gocritic, revive, sloglint, testifylint
- Banned packages: io/ioutil (use os/io), github.com/pkg/errors (use errors/fmt), golang.org/x/exp/slices (use slices)
- Local import prefix: github.com/grafana/generate-renovate-config
