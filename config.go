package main

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v4"
)

type config struct {
	// UnmaintainedVersions contains any major.minor versions that Renovate should not maintain.
	UnmaintainedVersions []string `yaml:"unmaintained_versions"`
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

	return cfg, nil
}
