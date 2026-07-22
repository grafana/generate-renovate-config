# generate-renovate-config

Go tool for generating [Renovate](https://renovatebot.com/) configuration file for a Go repository.
Renovate is configured not to update dependencies pinned through `replace` directives in the go.mod file.
Generated configurations group all `golang.org/x/**` Go module updates together across update types,
including major updates. Routine dependency updates remain disabled on release branches, while
vulnerability fixes use a distinct `golang.org/x` security group on every configured base branch.

## Configuration file

If the target repository contains a `.generate-renovate-config.yml` file, it's read for repository specific configuration:

```yaml
# Major.minor versions that Renovate should not maintain, even if their release branches
# would otherwise be detected as maintained.
unmaintained_versions: ['3.0']
# Container images that are digest-pinned (image@sha256:...) in repository files.
# A Renovate custom manager is generated per entry, tracking the image's `latest` tag
# and bumping the pinned digest as the tag advances.
digest_pinned_images:
  - image: us-docker.pkg.dev/grafanalabs-global/docker-deployment-tools-prod/cortex-rt
    file_patterns: ['.github/workflows/ci.yml']
# Custom package rules appended verbatim to the generated Renovate packageRules array.
# Keys are passed through to JSON unchanged, so any Renovate packageRules field is accepted.
# Rules are appended after the ones this tool generates, and Renovate merges matching rules
# with later entries winning, so a custom rule's fields take precedence over a generated rule
# only where both match the same package; otherwise the custom rule is simply added.
# Field names are NOT validated by this tool: a typo (e.g. matchPackageName instead of
# matchPackageNames) is emitted as-is and silently ignored by Renovate. The generated
# renovate.json references the Renovate $schema, so validate the result with Renovate's config
# validator or a --dry-run (see "Testing Generated Config" in AGENTS.md).
package_rules:
  - description: Slow down major updates for foo/bar
    matchPackageNames: ['foo/bar']
    matchUpdateTypes: ['major']
    minimumReleaseAge: '7 days'
```
