package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

var (
	auditPath string

	auditTailN        int
	auditTailFollow   bool
	auditTailJSON     bool
	auditTailInterval time.Duration

	auditFilterAgent    string
	auditFilterDecision string
	auditFilterSince    string

	auditVerifyAnchor        string
	auditVerifyPubKey        string
	auditVerifyRequireSigned bool

	auditHeadJSON bool

	auditExportFormat string

	auditKeygenPath string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect, verify, anchor and export the tamper-evident decision log",
	Long: `The audit log is a hash-chained (optionally Ed25519-signed) JSONL record of every
authorization decision, rotated into audit-<time>-<seq>.jsonl files.

A local attacker running as your user can rewrite and re-sign local history, so periodically
record "nexus-cli audit head" somewhere off the machine and check it later with
"nexus-cli audit verify --anchor <hash>". See docs/audit.md.`,
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Show the most recent authorization decisions (optionally following new ones)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := auditLogPath()
		if err != nil {
			return err
		}
		filter, err := auditFilter()
		if err != nil {
			return err
		}
		all, err := audit.ReadAll(path)
		if err != nil {
			return err
		}
		head := ""
		if len(all) > 0 {
			head = all[len(all)-1].Hash
		}
		entries := filter.Apply(all)
		if auditTailN > 0 && len(entries) > auditTailN {
			entries = entries[len(entries)-auditTailN:]
		}
		out := cmd.OutOrStdout()
		if len(entries) == 0 && !auditTailFollow && !auditTailJSON {
			fmt.Fprintln(out, "(no audit entries yet)")
			return nil
		}
		for _, e := range entries {
			if err := printTailEntry(out, e); err != nil {
				return err
			}
		}
		if !auditTailFollow {
			return nil
		}
		ctx, stop := signal.NotifyContext(commandContext(cmd), os.Interrupt)
		defer stop()
		return audit.Follow(ctx, path, head, auditTailInterval, func(e audit.Entry) error {
			if !filter.Match(e) {
				return nil
			}
			return printTailEntry(out, e)
		})
	},
}

func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func printTailEntry(w io.Writer, e audit.Entry) error {
	if auditTailJSON {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", b)
		return err
	}
	extra := ""
	if e.Source != "" {
		extra += " [" + e.Source + "]"
	}
	if e.Rule != "" {
		extra += " rule=" + e.Rule
	}
	_, err := fmt.Fprintf(w, "%s  %-5s  agent=%s act_as=%s  %s %s  %s%s\n",
		e.Time.Local().Format("2006-01-02T15:04:05"), e.Decision, e.Agent, e.ActAs, e.Tool, e.Target, e.Reason, extra)
	return err
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the hash chain, signatures and (optionally) an external anchor",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := auditLogPath()
		if err != nil {
			return err
		}
		opts, keyNote, err := auditVerifyOptions()
		if err != nil {
			return err
		}
		opts.Anchor = strings.TrimSpace(auditVerifyAnchor)
		opts.RequireSigned = auditVerifyRequireSigned
		res, err := audit.VerifyWithOptions(path, opts)
		if err != nil {
			return fmt.Errorf("audit chain INVALID: %w", err)
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "✔ audit chain intact: %d entries verified across %d file(s) (%d signed, %d unsigned)\n",
			res.Entries, res.Files, res.Signed, res.Unsigned)
		switch {
		case res.Signed > 0 && res.SigsChecked:
			fmt.Fprintf(out, "  signatures verified with %s\n", keyNote)
		case res.Signed > 0:
			fmt.Fprintln(out, "  signatures NOT checked: no audit public key (use --pubkey)")
		}
		if res.Entries > 0 {
			fmt.Fprintf(out, "  head: seq %d  %s\n", res.HeadSeq, res.Head)
		}
		if opts.Anchor != "" {
			fmt.Fprintf(out, "  anchor found at seq %d\n", res.AnchorSeq)
		}
		return nil
	},
}

// auditVerifyOptions loads public keys from --pubkey, or from the default audit.pub when present.
func auditVerifyOptions() (audit.VerifyOptions, string, error) {
	var opts audit.VerifyOptions
	p := auditVerifyPubKey
	explicit := p != ""
	if !explicit {
		var err error
		if p, err = audit.DefaultPubKeyPath(); err != nil {
			return opts, "", err
		}
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return opts, "", nil
		}
	}
	keys, err := audit.LoadPublicKeys(p)
	if err != nil {
		return opts, "", err
	}
	opts.PublicKeys = keys
	return opts, p, nil
}

var auditHeadCmd = &cobra.Command{
	Use:   "head",
	Short: "Print the verified chain head (seq, hash, time) to record off-machine as an anchor",
	Long: `Verifies the log and prints its newest entry's seq, hash and time.

Store this output somewhere a local attacker can't rewrite (a git commit, a ticket, a remote
log). Later, "nexus-cli audit verify --anchor <hash>" proves history up to that point is intact.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := auditLogPath()
		if err != nil {
			return err
		}
		opts, _, err := auditVerifyOptions()
		if err != nil {
			return err
		}
		res, err := audit.VerifyWithOptions(path, opts)
		if err != nil {
			return fmt.Errorf("audit chain INVALID: %w", err)
		}
		if res.Entries == 0 {
			return errors.New("audit log is empty")
		}
		out := cmd.OutOrStdout()
		if auditHeadJSON {
			return json.NewEncoder(out).Encode(map[string]any{
				"seq": res.HeadSeq, "hash": res.Head, "ts": res.HeadTime.UTC(), "entries": res.Entries,
			})
		}
		fmt.Fprintf(out, "seq   %d\nhash  %s\ntime  %s\n", res.HeadSeq, res.Head, res.HeadTime.UTC().Format(time.RFC3339))
		return nil
	},
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Write audit entries to stdout as JSONL or CSV",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := auditLogPath()
		if err != nil {
			return err
		}
		filter, err := auditFilter()
		if err != nil {
			return err
		}
		all, err := audit.ReadAll(path)
		if err != nil {
			return err
		}
		entries := filter.Apply(all)
		switch strings.ToLower(auditExportFormat) {
		case "jsonl", "json", "":
			return audit.WriteJSONL(cmd.OutOrStdout(), entries)
		case "csv":
			return audit.WriteCSV(cmd.OutOrStdout(), entries)
		default:
			return fmt.Errorf("unknown --format %q (want jsonl or csv)", auditExportFormat)
		}
	},
}

var auditKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Create (if needed) the audit signing key and print its public key",
	RunE: func(cmd *cobra.Command, args []string) error {
		kp := auditKeygenPath
		if kp == "" {
			var err error
			if kp, err = audit.DefaultKeyPath(); err != nil {
				return err
			}
		}
		priv, err := audit.LoadOrCreateKey(kp)
		if err != nil {
			return err
		}
		pub := priv.Public().(ed25519.PublicKey)
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "public key  %s\nkey id      %s\nprivate     %s\npublic file %s\n",
			audit.EncodePublicKey(pub), audit.KeyID(pub), kp, audit.PublicKeyPath(kp))
		return nil
	},
}

func auditFilter() (audit.Filter, error) {
	since, err := audit.ParseSince(auditFilterSince, time.Now())
	if err != nil {
		return audit.Filter{}, err
	}
	d := strings.ToLower(auditFilterDecision)
	if d != "" && d != "allow" && d != "deny" {
		return audit.Filter{}, fmt.Errorf("invalid --decision %q (want allow or deny)", auditFilterDecision)
	}
	return audit.Filter{Since: since, Agent: auditFilterAgent, Decision: d}, nil
}

func auditLogPath() (string, error) {
	if auditPath != "" {
		return auditPath, nil
	}
	// Honour `audit.path` from ./nexus.yaml so verify/tail read the log dev/run actually write.
	if cfg, exists, err := loadConfig("nexus.yaml"); err == nil && exists {
		return cfg.Audit.ResolvedPath()
	}
	return audit.DefaultPath()
}

func addAuditFilterFlags(c *cobra.Command) {
	c.Flags().StringVar(&auditFilterAgent, "agent", "", "Only entries for this agent")
	c.Flags().StringVar(&auditFilterDecision, "decision", "", "Only allow or deny entries")
	c.Flags().StringVar(&auditFilterSince, "since", "", "Only entries newer than a duration (24h, 7d) or RFC 3339 time")
}

func init() {
	auditCmd.PersistentFlags().StringVar(&auditPath, "file", "", "Path to the active audit log (default $NEXUS_HOME/audit.jsonl or ~/.nexus/audit.jsonl)")

	auditTailCmd.Flags().IntVarP(&auditTailN, "num", "n", 20, "Number of recent entries to show (0 = all)")
	auditTailCmd.Flags().BoolVarP(&auditTailFollow, "follow", "f", false, "Keep printing new entries (follows rotation)")
	auditTailCmd.Flags().BoolVar(&auditTailJSON, "json", false, "Print raw JSON lines")
	auditTailCmd.Flags().DurationVar(&auditTailInterval, "interval", audit.DefaultFollowInterval, "Polling interval for --follow")
	_ = auditTailCmd.Flags().MarkHidden("interval")
	addAuditFilterFlags(auditTailCmd)

	auditVerifyCmd.Flags().StringVar(&auditVerifyAnchor, "anchor", "", "Fail unless the chain contains this entry hash (from 'audit head')")
	auditVerifyCmd.Flags().StringVar(&auditVerifyPubKey, "pubkey", "", "Audit public key file (default audit.pub next to the audit key, if present)")
	auditVerifyCmd.Flags().BoolVar(&auditVerifyRequireSigned, "require-signed", false, "Fail on any unsigned entry")

	auditHeadCmd.Flags().BoolVar(&auditHeadJSON, "json", false, "Print as JSON")
	auditHeadCmd.Flags().StringVar(&auditVerifyPubKey, "pubkey", "", "Audit public key file (default audit.pub next to the audit key, if present)")

	auditExportCmd.Flags().StringVar(&auditExportFormat, "format", "jsonl", "Output format: jsonl or csv")
	addAuditFilterFlags(auditExportCmd)

	auditKeygenCmd.Flags().StringVar(&auditKeygenPath, "key", "", "Signing key path (default $NEXUS_HOME/audit.key)")

	auditCmd.AddCommand(auditTailCmd, auditVerifyCmd, auditHeadCmd, auditExportCmd, auditKeygenCmd)
	rootCmd.AddCommand(auditCmd)
}
