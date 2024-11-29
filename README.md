# generate-renovate-config

Go tool for generating [Renovate](https://renovatebot.com/) configuration file based on a go.mod file.
Renovate is configured not to update dependencies pinned through `replace` directives in the go.mod file.
