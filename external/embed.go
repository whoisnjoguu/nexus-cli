// Package external holds embedded project-scaffolding templates written by `nexus-cli init`.
package external

import (
	_ "embed"
	"strings"
)

//go:embed nexus.yaml
var Policy string

//go:embed claude-mcp.json
var claudeTmpl string

//go:embed vscode-mcp.json
var vscodeTmpl string

// mcpArgs is the JSON args array contents for the MCP server invocation.
func mcpArgs(strict bool) string {
	if strict {
		return `"mcp", "serve", "--strict"`
	}
	return `"mcp", "serve"`
}

// ClaudeMCP renders the Claude Code MCP config (mcpServers schema).
func ClaudeMCP(strict bool) string {
	return strings.Replace(claudeTmpl, "__ARGS__", mcpArgs(strict), 1)
}

// VSCodeMCP renders the VS Code / Copilot MCP config (servers + type schema).
func VSCodeMCP(strict bool) string {
	return strings.Replace(vscodeTmpl, "__ARGS__", mcpArgs(strict), 1)
}
