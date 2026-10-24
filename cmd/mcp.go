package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/mcp"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

var (
	mcpStrict          bool
	mcpKey             string
	mcpPolicy          string
	mcpAgentID         string
	mcpGateway         string
	mcpNoAudit         bool
	mcpHTTPAddr        string
	mcpHTTPToken       string
	mcpHTTPHosts       []string
	mcpAlsoStdio       bool
	mcpCallTimeout     time.Duration
	mcpApprovalTimeout time.Duration
	mcpNoRestart       bool
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Model Context Protocol gateway commands",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve nexus-cli as an MCP server / gateway for agent hosts (Claude Code, etc.)",
	Long: `Serve the Nexus MCP gateway. By default it speaks MCP over stdio (the agent host spawns it).
With --http it serves MCP Streamable HTTP at http://<addr>/mcp instead (add --stdio for both),
protected by a bearer token. Upstream MCP servers are configured under mcp.upstreams in the
policy file; see docs/mcp.md.

Approvals: when a call needs a human, the gateway asks the client via MCP elicitation if it
supports it, and in any case queues the request for ` + "`nexus-cli approve`" + ` in another terminal.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveKeyPath(mcpKey)
		if err != nil {
			return err
		}
		signer, err := jwt.LoadOrCreateSigner(path)
		if err != nil {
			return err
		}

		mcfg := mcp.Config{
			Signer:          signer,
			Strict:          mcpStrict,
			AgentID:         mcpAgentID,
			Version:         buildVersion,
			CallTimeout:     mcpCallTimeout,
			ApprovalTimeout: mcpApprovalTimeout,
			DisableRestart:  mcpNoRestart,
			PolicyPath:      mcpAbsPath(mcpPolicy),
		}
		if dir, derr := mcp.StatusDir(); derr == nil {
			mcfg.StatusDir = dir
		}

		if cfg, exists, cerr := loadConfig(mcpPolicy); cerr != nil {
			return cerr
		} else if exists {
			mcfg.Engine = policy.NewEngine(cfg.Policy)
			mcfg.Upstreams = cfg.MCP.Upstreams
		} else {
			mcfg.Engine = policy.NewEngine(policy.DefaultPolicy())
		}
		mcfg.OnPersistRule = func(rule policy.Rule) {
			if err := appendPolicyRule(mcpPolicy, rule); err != nil {
				fmt.Fprintf(os.Stderr, "note: could not persist rule to %s: %v\n", mcpPolicy, err)
			}
		}

		// Bind act_as to the logged-in human so the agent cannot forge it, and expose the human's
		// existing broker connections to the request_access / credential tools.
		gateway := mcpGateway
		if gateway == "" {
			gateway = os.Getenv("NEXUS_GATEWAY_URL")
		}
		if p, perr := loadPrincipal(); perr == nil && p != nil && p.Valid() {
			mcfg.ActAs = p.Subject
			mcfg.Ceiling = p.Scopes
			mcfg.Session = p
			if gateway == "" {
				gateway = p.GatewayURL
			}
		}
		mcfg.Gateway = gateway
		if sp, serr := principal.DefaultSessionPath(); serr == nil {
			mcfg.SessionPath = sp
		}

		if !mcpNoAudit {
			lg, _, aerr := openAuditLog(mcpPolicy)
			if aerr != nil {
				return aerr
			}
			defer lg.Close()
			mcfg.Audit = lg
		}

		// Out-of-band approvals: `nexus-cli approve` (another terminal) can answer HITL prompts,
		// racing MCP elicitation when the client supports it.
		cwd, _ := os.Getwd()
		broker := hitl.NewBroker(mcpApprovalTimeout)
		if ctrl, cerr := control.Start(broker, control.Info{Kind: "mcp", Policy: mcfg.PolicyPath, CWD: cwd, Listen: mcpHTTPAddr}); cerr != nil {
			fmt.Fprintf(os.Stderr, "[nexus-mcp] note: out-of-band approvals unavailable: %v\n", cerr)
		} else {
			mcfg.Approver = broker
			defer ctrl.Close()
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		server, err := mcp.New(mcfg)
		if err != nil {
			return fmt.Errorf("start mcp gateway: %w", err)
		}
		defer server.Close()

		if mcpHTTPAddr == "" {
			return server.Serve()
		}
		return serveMCPHTTP(ctx, server, os.Stderr)
	},
}

// serveMCPHTTP serves Streamable HTTP until ctx ends (and, with --stdio, until stdin closes).
func serveMCPHTTP(ctx context.Context, server *mcp.Server, logw io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ln, err := net.Listen("tcp", mcpHTTPAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", mcpHTTPAddr, err)
	}
	addr := ln.Addr().String()
	if !mcpIsLoopbackAddr(addr) {
		fmt.Fprintf(logw, "[nexus-mcp] WARNING: serving MCP on non-loopback address %s; anyone who can reach it and holds the token can drive your agent's tools\n", addr)
	}
	token := mcpHTTPToken
	if token == "" {
		token = mcp.NewSessionID()
		path, werr := writeHTTPToken(token)
		if werr != nil {
			_ = ln.Close()
			return werr
		}
		defer os.Remove(path)
		fmt.Fprintf(logw, "[nexus-mcp] bearer token (also in %s): %s\n", path, token)
	}
	fmt.Fprintf(logw, "[nexus-mcp] MCP endpoint: http://%s/mcp\n", addr)
	server.SetHTTPAddr(addr)

	errc := make(chan error, 2)
	go func() {
		errc <- server.ServeStreamableHTTP(ctx, ln, mcp.HTTPOptions{Token: token, AllowedHosts: mcpHTTPHosts})
	}()
	if mcpAlsoStdio {
		go func() {
			err := server.Serve()
			cancel() // stdin closed: the host is gone
			errc <- err
		}()
	}
	err = <-errc
	cancel()
	return err
}

// writeHTTPToken stores a generated bearer token at <nexus home>/mcp/http.token (0600).
func writeHTTPToken(token string) (string, error) {
	dir, err := mcp.StatusDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "http.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, os.Chmod(path, 0o600)
}

func mcpIsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func mcpAbsPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func newMCPStatusCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Show running MCP gateways and the state of their upstream servers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := mcp.StatusDir()
			if err != nil {
				return err
			}
			files, err := mcp.ReadStatusFiles(dir)
			if err != nil {
				return err
			}
			files, removed := mcp.CleanStatusFiles(files)
			if removed > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "removed %d status file(s) left by exited gateways\n", removed)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				if files == nil {
					files = []mcp.StatusFile{}
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(files)
			}
			return printMCPStatus(out, files, dir, time.Now())
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print raw status JSON")
	return c
}

func printMCPStatus(out io.Writer, files []mcp.StatusFile, dir string, now time.Time) error {
	if len(files) == 0 {
		fmt.Fprintf(out, "no running nexus-cli MCP gateways (status dir: %s)\n", dir)
		return nil
	}
	for i, f := range files {
		if i > 0 {
			fmt.Fprintln(out)
		}
		state := "running"
		if f.Stale(now) {
			state = fmt.Sprintf("stale (no update for %s; process may have exited)", mcpAgo(now, f.Updated))
		}
		fmt.Fprintf(out, "gateway pid %d (%s) %s, up %s\n", f.PID, f.Version, state, mcpAgo(now, f.Started))
		if f.CWD != "" {
			fmt.Fprintf(out, "  cwd:      %s\n", f.CWD)
		}
		if f.Policy != "" {
			fmt.Fprintf(out, "  policy:   %s\n", f.Policy)
		}
		if f.HTTP != "" {
			fmt.Fprintf(out, "  http:     http://%s/mcp\n", f.HTTP)
		}
		fmt.Fprintf(out, "  sessions: %d\n", f.Sessions)
		if len(f.Upstreams) == 0 {
			fmt.Fprintln(out, "  (no upstream servers configured)")
			continue
		}
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  UPSTREAM\tTRANSPORT\tSTATE\tTOOLS\tRESTARTS\tSINCE\tLAST ERROR")
		for _, u := range f.Upstreams {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%d\t%s\t%s\n", u.Name, u.Transport, u.State, u.Tools, u.Restarts, mcpAgo(now, u.Since), mcpOneLine(u.LastError))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func mcpAgo(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	return d.Round(time.Second).String()
}

func mcpOneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

var errNoHTTPForStdio = errors.New("--stdio only makes sense together with --http")

func init() {
	mcpServeCmd.Flags().BoolVar(&mcpStrict, "strict", false, "Require HITL approval for every tool call")
	mcpServeCmd.Flags().StringVar(&mcpKey, "key", "", "Path to the persistent Ed25519 key (default ~/.nexus/ed25519.key)")
	mcpServeCmd.Flags().StringVar(&mcpPolicy, "policy", "nexus.yaml", "Path to the policy/gateway config file")
	mcpServeCmd.Flags().StringVar(&mcpAgentID, "agent-id", "mcp-agent", "Agent identity to attribute tool calls to")
	mcpServeCmd.Flags().StringVar(&mcpGateway, "gateway", "", "nexus-framework Gateway URL for broker-access tools (or NEXUS_GATEWAY_URL / session)")
	mcpServeCmd.Flags().BoolVar(&mcpNoAudit, "no-audit", false, "Disable the tamper-evident audit log")
	mcpServeCmd.Flags().StringVar(&mcpHTTPAddr, "http", "", "Serve MCP Streamable HTTP on this address (e.g. 127.0.0.1:8765) instead of stdio")
	mcpServeCmd.Flags().StringVar(&mcpHTTPToken, "http-token", "", "Bearer token HTTP clients must send (default: generated, written to <nexus home>/mcp/http.token)")
	mcpServeCmd.Flags().StringSliceVar(&mcpHTTPHosts, "http-allowed-host", nil, "Extra Host header names accepted besides loopback (needed for non-loopback binds)")
	mcpServeCmd.Flags().BoolVar(&mcpAlsoStdio, "stdio", false, "With --http, also serve stdio")
	mcpServeCmd.Flags().DurationVar(&mcpCallTimeout, "call-timeout", mcp.DefaultCallTimeout, "Timeout for each request forwarded to an upstream server")
	mcpServeCmd.Flags().DurationVar(&mcpApprovalTimeout, "approval-timeout", mcp.DefaultApprovalTimeout, "How long to wait for a human approval before denying")
	mcpServeCmd.Flags().BoolVar(&mcpNoRestart, "no-restart", false, "Do not restart upstream servers that exit")
	mcpServeCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if mcpAlsoStdio && mcpHTTPAddr == "" {
			return errNoHTTPForStdio
		}
		return nil
	}

	mcpCmd.AddCommand(mcpServeCmd)
	mcpCmd.AddCommand(newMCPStatusCmd())
	rootCmd.AddCommand(mcpCmd)
}
