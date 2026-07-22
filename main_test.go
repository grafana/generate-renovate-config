package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildRenovateConfig_GroupsGolangXUpdates(t *testing.T) {
	branchProps := []branchProperties{
		{name: "", replaced: []string{"golang.org/x/exp"}, goVersion: "1.22.4"},
		{name: "gem-release-1.0", replaced: nil, goVersion: "1.21.12"},
	}

	cfg, err := buildRenovateConfig("master", branchProps, renderOpts{})
	require.NoError(t, err)

	var groupRule packageRules
	found := false
	for _, rawRule := range cfg.PackageRules {
		rule, ok := rawRule.(packageRules)
		if ok && rule.Description == "Group golang.org/x module updates" {
			groupRule = rule
			found = true
			break
		}
	}
	require.True(t, found)
	require.Equal(t, []string{"go"}, groupRule.MatchDatasources)
	require.Equal(t, []string{"golang.org/x/**"}, groupRule.MatchPackageNames)
	require.Equal(t, "golang.org/x", groupRule.GroupName)
	require.Empty(t, groupRule.MatchBaseBranches)
	require.Nil(t, groupRule.Enabled)
	require.NotNil(t, groupRule.SeparateMajorMinor)
	require.False(t, *groupRule.SeparateMajorMinor)

	require.True(t, cfg.VulnerabilityAlerts.Enabled)
	require.Equal(t, []string{"security-update"}, cfg.VulnerabilityAlerts.Labels)
	require.Equal(t, "{{#if (and (equals datasource 'go') (containsString depName 'golang.org/x/'))}}golang.org/x security updates{{else}}dependency {{{depName}}}{{/if}}", cfg.VulnerabilityAlerts.GroupName)
	require.Equal(t, "{{#if (and (equals datasource 'go') (containsString depName 'golang.org/x/'))}}golang-org-x-security{{else}}{{{datasource}}}-{{{depNameSanitized}}}-vulnerability{{/if}}", cfg.VulnerabilityAlerts.GroupSlug)
	require.True(t, cfg.OSVVulnerabilityAlerts)
	require.Equal(t, []string{"master", "gem-release-1.0"}, cfg.BaseBranches)
}

func TestBuildRenovateConfig_PackageRuleEnabledSerialization(t *testing.T) {
	branchProps := []branchProperties{
		{name: "", replaced: []string{"example.com/replaced"}, goVersion: "1.22.4"},
	}

	cfg, err := buildRenovateConfig("master", branchProps, renderOpts{})
	require.NoError(t, err)

	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	var parsed struct {
		PackageRules []map[string]any `json:"packageRules"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))

	rulesByDescription := make(map[string]map[string]any, len(parsed.PackageRules))
	for _, rule := range parsed.PackageRules {
		description, ok := rule["description"].(string)
		require.True(t, ok)
		rulesByDescription[description] = rule
	}

	groupRule := rulesByDescription["Group golang.org/x module updates"]
	require.NotNil(t, groupRule)
	require.NotContains(t, groupRule, "enabled")
	require.Equal(t, false, groupRule["separateMajorMinor"])
	require.Equal(t, false, rulesByDescription["Disable updating of replaced dependencies for default branch"]["enabled"])
	require.Equal(t, true, rulesByDescription["Pin Go at the current version for the default branch"]["enabled"])
}

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
