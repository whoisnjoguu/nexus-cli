package mcp

// SupportedProtocolVersions lists the MCP protocol revisions the gateway speaks, oldest first.
var SupportedProtocolVersions = []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}

// LatestProtocolVersion is the newest revision in SupportedProtocolVersions.
const LatestProtocolVersion = "2025-11-25"

const serverName = "nexus-security-guardrail"

// negotiateVersion echoes the client's requested revision when supported, else offers our latest.
func negotiateVersion(requested string) string {
	if isSupportedVersion(requested) {
		return requested
	}
	return LatestProtocolVersion
}

func isSupportedVersion(v string) bool {
	for _, s := range SupportedProtocolVersions {
		if s == v {
			return true
		}
	}
	return false
}
