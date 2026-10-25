package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
)

var (
	caDir          string
	caPathBundle   bool
	caInstallRun   bool
	caUninstallRun bool
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage the local CA used to intercept agent HTTPS traffic",
	Long: `The local certificate authority lets the proxy terminate TLS for agent traffic so that full
policy (methods, paths, bodies) applies to HTTPS requests, not just CONNECT host gating.
The CA private key never leaves this machine.`,
}

var caInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create the local CA (or show the existing one)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := resolveCADir()
		if err != nil {
			return err
		}
		c, err := ca.LoadOrCreate(dir)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "CA certificate: %s\n", c.CertPath())
		fmt.Fprintf(out, "SHA-256 fingerprint: %s\n", c.Fingerprint())
		fmt.Fprintln(out, "\nNext steps:")
		fmt.Fprintln(out, "  nexus-cli ca install      # trust the CA system-wide (optional)")
		fmt.Fprintln(out, "  nexus-cli run -- <agent>  # sets CA env vars (SSL_CERT_FILE etc.) for the agent automatically")
		return nil
	},
}

var caPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the CA certificate path (or, with --bundle, write and print a combined bundle)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadCA()
		if err != nil {
			return err
		}
		if caPathBundle {
			if err := c.WriteBundle(c.BundlePath()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), c.BundlePath())
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), c.CertPath())
		return nil
	},
}

var caFingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Print the SHA-256 fingerprint of the CA certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadCA()
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), c.Fingerprint())
		return nil
	},
}

var caInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Show (or with --run, execute) the commands that trust the CA in the OS store",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadCA()
		if err != nil {
			return err
		}
		return runTrustCommands(cmd, "install", ca.InstallCommands(runtime.GOOS, c.CertPath()), caInstallRun)
	},
}

var caUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Show (or with --run, execute) the commands that remove the CA from the OS store",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := loadCA()
		if err != nil {
			return err
		}
		return runTrustCommands(cmd, "uninstall", ca.UninstallCommands(runtime.GOOS, c.CertPath()), caUninstallRun)
	},
}

func resolveCADir() (string, error) {
	if caDir != "" {
		return caDir, nil
	}
	return ca.DefaultDir()
}

func loadCA() (*ca.CA, error) {
	dir, err := resolveCADir()
	if err != nil {
		return nil, err
	}
	c, err := ca.Load(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w\nhint: run `nexus-cli ca init` first", err)
		}
		return nil, err
	}
	return c, nil
}

func runTrustCommands(cmd *cobra.Command, verb string, cmds [][]string, run bool) error {
	out := cmd.OutOrStdout()
	if len(cmds) == 0 {
		return fmt.Errorf("automatic %s is not supported on %s; add/remove the certificate in your OS trust store manually", verb, runtime.GOOS)
	}
	if !run {
		fmt.Fprintf(out, "Run the following to %s the nexus-cli CA (or re-run with --run):\n\n", verb)
	}
	for _, argv := range cmds {
		fmt.Fprintf(out, "  %s\n", shellJoin(argv))
	}
	fmt.Fprintln(out, "\nNote: Firefox/NSS and Java keep their own trust stores; import the certificate there separately if needed.")
	if !run {
		return nil
	}
	for _, argv := range cmds {
		fmt.Fprintf(out, "\n$ %s\n", shellJoin(argv))
		c := exec.Command(argv[0], argv[1:]...)
		c.Stdin, c.Stdout, c.Stderr = cmd.InOrStdin(), out, cmd.ErrOrStderr()
		if err := c.Run(); err != nil {
			return fmt.Errorf("%s failed: %w", shellJoin(argv), err)
		}
	}
	fmt.Fprintf(out, "\nCA %s complete.\n", verb)
	return nil
}

// shellJoin renders argv for display, quoting arguments that contain spaces or quotes.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\"'$\\") {
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

func init() {
	defDir, _ := ca.DefaultDir()
	caCmd.PersistentFlags().StringVar(&caDir, "dir", defDir, "Directory holding ca.crt and ca.key")
	caPathCmd.Flags().BoolVar(&caPathBundle, "bundle", false, "Write <dir>/bundle.pem (system roots + CA) and print its path")
	caInstallCmd.Flags().BoolVar(&caInstallRun, "run", false, "Execute the commands instead of just printing them")
	caUninstallCmd.Flags().BoolVar(&caUninstallRun, "run", false, "Execute the commands instead of just printing them")
	caCmd.AddCommand(caInitCmd, caPathCmd, caFingerprintCmd, caInstallCmd, caUninstallCmd)
	rootCmd.AddCommand(caCmd)
}
