package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v4"
)

type config struct {
	// UnmaintainedVersions contains any major.minor versions that Renovate should not maintain.
	UnmaintainedVersions []string `yaml:"unmaintained_versions"`
	// DigestPinnedImages contains container images that are digest-pinned in repository files,
	// for which custom managers are generated so that Renovate keeps the digests bumped.
	DigestPinnedImages []digestPinnedImage `yaml:"digest_pinned_images"`
	// PackageRules are appended verbatim to the generated Renovate packageRules array.
	// Keys are passed through to JSON unchanged, so any Renovate packageRules field is accepted.
	// They are appended last, so they override the rules this tool generates.
	PackageRules []map[string]any `yaml:"package_rules"`
}

// digestPinnedImage describes a container image referenced by digest (image@sha256:...)
// in repository files. A Renovate custom manager is generated per entry, tracking the
// image's `latest` tag and bumping the pinned digest as the tag advances.
type digestPinnedImage struct {
	// Image is the full image reference, without tag or digest.
	Image string `yaml:"image"`
	// FilePatterns are the Renovate managerFilePatterns to search for digest references.
	FilePatterns []string `yaml:"file_patterns"`
}

func (c config) validate() error {
	for i, img := range c.DigestPinnedImages {
		if img.Image == "" {
			return fmt.Errorf("digest_pinned_images[%d]: image must not be empty", i)
		}
		if strings.Contains(img.Image, "@") {
			return fmt.Errorf("digest_pinned_images[%d]: image %q must not include a digest", i, img.Image)
		}
		if lastSegment := img.Image[strings.LastIndex(img.Image, "/")+1:]; strings.Contains(lastSegment, ":") {
			return fmt.Errorf("digest_pinned_images[%d]: image %q must not include a tag", i, img.Image)
		}
		if len(img.FilePatterns) == 0 {
			return fmt.Errorf("digest_pinned_images[%d]: file_patterns must not be empty", i)
		}
	}
	for i, r := range c.PackageRules {
		if len(r) == 0 {
			return fmt.Errorf("package_rules[%d]: must not be empty", i)
		}
	}
	return nil
}

func readConfig(repoPath string) (config, error) {
	p := filepath.Join(repoPath, ".generate-renovate-config.yml")
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return config{}, nil
		}
		return config{}, fmt.Errorf("read %q: %w", p, err)
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unmarshal %q: %w", p, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, fmt.Errorf("validate %q: %w", p, err)
	}

	return cfg, nil
}
