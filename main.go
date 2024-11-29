package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/template"

	"github.com/urfave/cli/v2"
)

//go:embed renovate.json5.tmpl
var tmplData string

type templateContext struct {
	Replaced []string
}

func main() {
	app := &cli.App{
		Name:      "generate-renovate-config",
		Usage:     "Generate Renovate configuration from a go.mod file",
		ArgsUsage: "<go.mod> <output>",
		Action: func(cCtx *cli.Context) error {
			if cCtx.Args().Len() != 2 {
				return fmt.Errorf("wrong number of arguments")
			}

			goModPath := cCtx.Args().Get(0)
			outputPath := cCtx.Args().Get(1)
			replaced, err := getReplaced(goModPath)
			if err != nil {
				return err
			}
			return renderConfig(replaced, outputPath)
		},
	}
	if err := app.Run(os.Args); err != nil {
		bail(err)
	}
}

func getReplaced(goModPath string) ([]string, error) {
	var replaced []string

	inputf, err := os.Open(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %q: %s", goModPath, err)
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
					return nil, fmt.Errorf("invalid replace directive format: %q", line)
				}
				replaced = append(replaced, parts[3])

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
			return nil, fmt.Errorf("invalid replace directive format: %q", line)
		}
		replaced = append(replaced, parts[2])
	}

	// Check for errors from the scanner
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %q: %s\n", goModPath, err)
	}

	return replaced, nil
}

func renderConfig(replaced []string, outputPath string) error {
	tmpl, err := template.New("renovate.json5.tmpl").Parse(tmplData)
	if err != nil {
		return fmt.Errorf("failed to parse template: %s", err)
	}

	outf, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %s", outputPath, err)
	}

	data := templateContext{
		Replaced: replaced,
	}
	if err := tmpl.Execute(outf, data); err != nil {
		_ = outf.Close()
		return fmt.Errorf("failed to execute template: %s", err)
	}

	if err := outf.Close(); err != nil {
		return fmt.Errorf("failed to write to %s: %s", outputPath, err)
	}
	return nil
}

func bail(err error) {
	slog.Error(err.Error())
	os.Exit(1)
}
