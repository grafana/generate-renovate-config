package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildRenovateConfig_CustomPackageRules(t *testing.T) {
	branchProps := []branchProperties{
		{name: "", replaced: []string{"example.com/replaced"}, goVersion: "1.22.4"},
	}

	custom := []map[string]any{
		{
			"description":       "Slow major updates",
			"matchPackageNames": []any{"foo/bar"},
			"matchUpdateTypes":  []any{"major"},
			"enabled":           false,
			"minimumReleaseAge": "7 days",
		},
		{
			"description":       "Group golang.org/x",
			"matchPackageNames": []any{"golang.org/x/*"},
			"groupName":         "golang-x",
		},
	}

	cfg, err := buildRenovateConfig("master", branchProps, renderOpts{
		customPackageRules: custom,
	})
	require.NoError(t, err)

	// Custom rules are appended last so they override generated rules in Renovate's
	// last-wins evaluation. Verify both the count and that they are the trailing entries,
	// in the same order they were given.
	require.GreaterOrEqual(t, len(cfg.PackageRules), len(custom))
	tail := cfg.PackageRules[len(cfg.PackageRules)-len(custom):]
	for i, want := range custom {
		require.Equal(t, want, tail[i])
	}
}

func TestBuildRenovateConfig_CustomPackageRulesMarshalToJSON(t *testing.T) {
	branchProps := []branchProperties{
		{name: "", replaced: nil, goVersion: "1.22.4"},
	}

	custom := []map[string]any{
		{
			"description":       "Custom",
			"matchPackageNames": []any{"foo/bar"},
			"enabled":           false,
		},
	}

	cfg, err := buildRenovateConfig("master", branchProps, renderOpts{
		customPackageRules: custom,
	})
	require.NoError(t, err)

	// The PackageRules field is []any holding a mix of typed packageRules and map[string]any
	// (from the custom rules). Verify json marshaling treats both kinds as plain JSON objects
	// and emits the custom rule's keys verbatim.
	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	var parsed struct {
		PackageRules []map[string]any `json:"packageRules"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.NotEmpty(t, parsed.PackageRules)

	last := parsed.PackageRules[len(parsed.PackageRules)-1]
	require.Equal(t, "Custom", last["description"])
	require.Equal(t, []any{"foo/bar"}, last["matchPackageNames"])
	require.Equal(t, false, last["enabled"])
}

func TestBuildRenovateConfig_NoCustomPackageRules(t *testing.T) {
	branchProps := []branchProperties{
		{name: "", replaced: nil, goVersion: "1.22.4"},
	}

	cfg, err := buildRenovateConfig("master", branchProps, renderOpts{})
	require.NoError(t, err)

	// Without custom rules, every entry should be a typed packageRules value.
	for i, r := range cfg.PackageRules {
		_, ok := r.(packageRules)
		require.Truef(t, ok, "PackageRules[%d] should be of type packageRules, got %T", i, r)
	}
}
