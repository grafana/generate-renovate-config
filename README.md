# generate-renovate-config

Go tool for generating [Renovate](https://renovatebot.com/) configuration file for a Go repository.
Renovate is configured not to update dependencies pinned through `replace` directives in the go.mod file.

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
```
