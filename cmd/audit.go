package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

var (
	auditPath  string
	auditTailN int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect and verify the tamper-evident decision log",
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Show the most recent authorization decisions",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := auditLogPath()
		if err != nil {
			return err
		}
		entries, err := audit.Tail(path, auditTailN)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Println("(no audit entries yet)")
			return nil
		}
		for _, e := range entries {
			fmt.Printf("%s  %-5s  agent=%s act_as=%s  %s %s  %s\n",
				e.Time.Format("2006-01-02T15:04:05"), e.Decision, e.Agent, e.ActAs, e.Tool, e.Target, e.Reason)
		}
		return nil
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the audit log's hash chain is intact (no tampering)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := auditLogPath()
		if err != nil {
			return err
		}
		n, err := audit.Verify(path)
		if err != nil {
			return fmt.Errorf("audit chain INVALID: %w", err)
		}
		fmt.Printf("✔ audit chain intact: %d entries verified\n", n)
		return nil
	},
}

func auditLogPath() (string, error) {
	if auditPath != "" {
		return auditPath, nil
	}
	return audit.DefaultPath()
}

func init() {
	auditCmd.PersistentFlags().StringVar(&auditPath, "file", "", "Path to the audit log (default ~/.nexus/audit.jsonl)")
	auditTailCmd.Flags().IntVarP(&auditTailN, "num", "n", 20, "Number of recent entries to show")

	auditCmd.AddCommand(auditTailCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}
