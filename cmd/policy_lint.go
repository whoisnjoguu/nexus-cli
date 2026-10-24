package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

var (
	plFile   string
	plJSON   bool
	plStrict bool
)

var policyLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Validate the policy file: unknown keys, bad actions/globs, dead or shadowed rules",
	Long: `Validate the policy file without starting anything.

Errors (unknown keys, unknown actions, malformed globs, one_time on a non-allow rule, inject
without a host, ...) make dev/run/mcp refuse to load the file. Warnings flag rules that load but
probably don't do what you meant (never-matching, unreachable, overly broad). Exits 1 on errors,
or on warnings too with --strict-warnings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := plFile
		out := cmd.OutOrStdout()
		issues, err := lintPolicyFile(path)
		if err != nil {
			return err
		}
		errs, warns := policy.CountIssues(issues)
		if plJSON {
			if issues == nil {
				issues = []policy.Issue{}
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"path": path, "errors": errs, "warnings": warns, "issues": issues}); err != nil {
				return err
			}
		} else {
			for _, is := range issues {
				fmt.Fprintln(out, is.String())
			}
			if len(issues) == 0 {
				fmt.Fprintf(out, "✔ %s: no issues\n", path)
			} else {
				fmt.Fprintf(out, "%s: %d error(s), %d warning(s)\n", path, errs, warns)
			}
		}
		if errs > 0 || (plStrict && warns > 0) {
			return exitCodeError{code: 1}
		}
		return nil
	},
}

// lintPolicyFile returns every parse and validation issue in the policy file at path.
func lintPolicyFile(path string) ([]policy.Issue, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no policy file at %s (run 'nexus-cli init')", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	cfg, err := decodeConfig(path, data)
	var perr *configParseError
	if errors.As(err, &perr) {
		return perr.issues, nil
	}
	if err != nil {
		return nil, err
	}
	return policy.Validate(cfg.Policy), nil
}

func init() {
	policyLintCmd.Flags().StringVar(&plFile, "policy", "nexus.yaml", "Path to the policy file")
	policyLintCmd.Flags().BoolVar(&plJSON, "json", false, "Print issues as JSON")
	policyLintCmd.Flags().BoolVar(&plStrict, "strict-warnings", false, "Exit 1 on warnings as well as errors")
	policyCmd.AddCommand(policyLintCmd)
}
