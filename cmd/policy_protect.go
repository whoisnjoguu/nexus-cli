package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/internal/atomicfile"
	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

const policyFlagHelp = "Path to the policy file (default: $NEXUS_POLICY, else $NEXUS_HOME/policy.yaml if it exists, else ./nexus.yaml)"

// resolvePolicyPath picks the active policy file: an explicit --policy flag, then $NEXUS_POLICY,
// then $NEXUS_HOME/policy.yaml when it exists (see `policy protect`), then ./nexus.yaml.
// cmd may be nil (no flag).
func resolvePolicyPath(cmd *cobra.Command) string {
	if cmd != nil {
		if f := cmd.Flags().Lookup("policy"); f != nil && f.Changed {
			return f.Value.String()
		}
	}
	if p := strings.TrimSpace(os.Getenv("NEXUS_POLICY")); p != "" {
		return p
	}
	if p, err := homePolicyPath(); err == nil && fileExists(p) {
		return p
	}
	return "nexus.yaml"
}

// homePolicyPath is the protected policy location, outside any agent workspace.
func homePolicyPath() (string, error) {
	h, err := audit.Home()
	if err != nil {
		return "", err
	}
	if abs, aerr := filepath.Abs(h); aerr == nil {
		h = abs
	}
	return filepath.Join(h, "policy.yaml"), nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// insideWorkspace reports whether path lies within the current directory (the agent's
// workspace for dev/run).
func insideWorkspace(path string) bool {
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(wd); err == nil {
		wd = r
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(r, filepath.Base(abs))
	}
	rel, err := filepath.Rel(wd, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// displayPath shows relative paths as ./x so the workspace warning reads naturally.
func displayPath(p string) string {
	if filepath.IsAbs(p) || strings.HasPrefix(p, ".") {
		return p
	}
	return "." + string(filepath.Separator) + p
}

// warnPolicyInWorkspace prints the workspace warning for dev/run.
func warnPolicyInWorkspace(w io.Writer, path string) {
	if insideWorkspace(path) {
		fmt.Fprintf(w, "[nexus] warning: policy %s is inside the agent's workspace — the agent could edit it; move it with 'nexus-cli policy protect' or rely on the built-in guard\n", displayPath(path))
	}
}

var protectKeep bool

var policyProtectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Move the policy out of the agent's workspace to $NEXUS_HOME/policy.yaml (0600)",
	Long: `Move the active policy file to $NEXUS_HOME/policy.yaml (~/.nexus/policy.yaml), mode 0600.

That location takes precedence over ./nexus.yaml (after --policy and $NEXUS_POLICY), so dev, run
and mcp serve pick it up with no flags. A pin for the old path moves with the file. --keep leaves
the original in place.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		src := resolvePolicyPath(cmd)
		dst, err := homePolicyPath()
		if err != nil {
			return err
		}
		pinFile, err := policy.PinPath()
		if err != nil {
			return err
		}
		srcAbs, _ := filepath.Abs(src)
		if srcAbs == dst {
			fmt.Fprintf(cmd.OutOrStdout(), "policy is already protected: %s\n", dst)
			return nil
		}
		data, err := os.ReadFile(src)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no policy file at %s (run 'nexus-cli init')", src)
		}
		if err != nil {
			return err
		}
		if fileExists(dst) {
			return fmt.Errorf("%s already exists; remove it first or pass --policy %s", dst, dst)
		}
		if _, err := parseConfig(src, data); err != nil {
			return fmt.Errorf("refusing to protect an invalid policy: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if sum, ok, err := policy.ReadPin(pinFile, src); err != nil {
			return err
		} else if ok {
			if err := policy.WritePin(pinFile, dst, sum); err != nil {
				return err
			}
		}
		if err := atomicfile.Write(dst, data, 0o600); err != nil {
			return err
		}
		if !protectKeep {
			if err := os.Remove(src); err != nil {
				return fmt.Errorf("copied to %s but could not remove %s: %w", dst, src, err)
			}
			_ = policy.WritePin(pinFile, src, "")
		}
		fmt.Fprintln(cmd.OutOrStdout(), dst)
		return nil
	},
}

var pinRemove bool

var policyPinCmd = &cobra.Command{
	Use:   "pin",
	Short: "Record the policy's sha256 so dev/run/mcp refuse unapproved changes",
	Long: `Write the sha256 of the active policy file to $NEXUS_HOME/policy.pin.

While a pin exists, dev, run and mcp serve refuse to start with (and hot reload refuses to load)
a policy whose hash differs, unless started with --accept-policy-change (which re-pins). Changes
made through nexus-cli itself (policy edit, "always allow" approvals) re-pin automatically.
Re-run this command after reviewing a hand edit. --remove deletes the pin.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := resolvePolicyPath(cmd)
		pinFile, err := policy.PinPath()
		if err != nil {
			return err
		}
		if pinRemove {
			if err := policy.WritePin(pinFile, path, ""); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "unpinned %s\n", path)
			return nil
		}
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no policy file at %s (run 'nexus-cli init')", path)
		}
		if err != nil {
			return err
		}
		if _, err := parseConfig(path, data); err != nil {
			return fmt.Errorf("refusing to pin an invalid policy: %w", err)
		}
		sum := policy.Sum(data)
		if err := policy.WritePin(pinFile, path, sum); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "pinned %s sha256:%s → %s\n", path, sum, pinFile)
		return nil
	},
}

func init() {
	policyProtectCmd.Flags().String("policy", "nexus.yaml", policyFlagHelp)
	policyProtectCmd.Flags().BoolVar(&protectKeep, "keep", false, "Copy instead of move (leave the original file)")
	policyPinCmd.Flags().String("policy", "nexus.yaml", policyFlagHelp)
	policyPinCmd.Flags().BoolVar(&pinRemove, "remove", false, "Remove the pin instead of writing it")
	policyCmd.AddCommand(policyProtectCmd, policyPinCmd)
}
