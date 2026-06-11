package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".generate-renovate-config.yml"), []byte(content), 0o644))
	return dir
}

func TestReadConfig(t *testing.T) {
	t.Run("missing file returns empty config", func(t *testing.T) {
		cfg, err := readConfig(t.TempDir())
		require.NoError(t, err)
		require.Empty(t, cfg.UnmaintainedVersions)
		require.Empty(t, cfg.DigestPinnedImages)
	})

	tests := map[string]struct {
		content string
		expErr  string
		expCfg  config
	}{
		"valid config": {
			content: `unmaintained_versions: ['3.0']
digest_pinned_images:
  - image: grafana/example
    file_patterns: ['.github/workflows/ci.yml']
`,
			expCfg: config{
				UnmaintainedVersions: []string{"3.0"},
				DigestPinnedImages: []digestPinnedImage{
					{
						Image:        "grafana/example",
						FilePatterns: []string{".github/workflows/ci.yml"},
					},
				},
			},
		},
		"registry port is not mistaken for a tag": {
			content: `digest_pinned_images:
  - image: registry.example.com:5000/repo/image
    file_patterns: ['Makefile']
`,
			expCfg: config{
				DigestPinnedImages: []digestPinnedImage{
					{
						Image:        "registry.example.com:5000/repo/image",
						FilePatterns: []string{"Makefile"},
					},
				},
			},
		},
		"image with tag fails validation": {
			content: `digest_pinned_images:
  - image: example.com/repo/image:latest
    file_patterns: ['Makefile']
`,
			expErr: `digest_pinned_images[0]: image "example.com/repo/image:latest" must not include a tag`,
		},
		"image with digest fails validation": {
			content: `digest_pinned_images:
  - image: example.com/repo/image@sha256:abcd
    file_patterns: ['Makefile']
`,
			expErr: `digest_pinned_images[0]: image "example.com/repo/image@sha256:abcd" must not include a digest`,
		},
		"empty image fails validation": {
			content: `digest_pinned_images:
  - file_patterns: ['Makefile']
`,
			expErr: "digest_pinned_images[0]: image must not be empty",
		},
		"empty file patterns fails validation": {
			content: `digest_pinned_images:
  - image: example.com/repo/image
`,
			expErr: "digest_pinned_images[0]: file_patterns must not be empty",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := readConfig(writeConfigFile(t, tc.content))
			if tc.expErr != "" {
				require.ErrorContains(t, err, tc.expErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expCfg, cfg)
		})
	}
}

func TestDigestPinManagers(t *testing.T) {
	mgrs := digestPinManagers([]digestPinnedImage{
		{
			Image:        "grafana/example",
			FilePatterns: []string{".github/workflows/ci.yml"},
		},
	})
	require.Len(t, mgrs, 1)

	mgr := mgrs[0]
	require.Equal(t, "regex", mgr.CustomType)
	require.Equal(t, []string{".github/workflows/ci.yml"}, mgr.ManagerFilePatterns)
	require.Equal(t, "docker", mgr.DatasourceTemplate)
	require.Equal(t, "latest", mgr.CurrentValueTemplate)
	require.Equal(t, []string{
		`(?<depName>grafana/example)@(?<currentDigest>sha256:[a-f0-9]+)`,
	}, mgr.MatchStrings)

	// Renovate evaluates matchStrings with RE2, whose only syntactical difference from Go's
	// regexp package here is the named capture groups ((?<name>...) instead of (?P<name>...)).
	// Translate and verify the expression against a realistic workflow line.
	re := regexp.MustCompile(strings.ReplaceAll(mgr.MatchStrings[0], "(?<", "(?P<"))
	line := "          grafana/example@sha256:9e118b49519e910a32a20b65df43b2b4b67aeefe205c679a4b8f395f737ca8b7 -v"
	ms := re.FindStringSubmatch(line)
	require.NotNil(t, ms)
	require.Equal(t, "grafana/example", ms[re.SubexpIndex("depName")])
	require.Equal(t, "sha256:9e118b49519e910a32a20b65df43b2b4b67aeefe205c679a4b8f395f737ca8b7", ms[re.SubexpIndex("currentDigest")])

	require.False(t, re.MatchString("grafana/example:latest -v"))
}
