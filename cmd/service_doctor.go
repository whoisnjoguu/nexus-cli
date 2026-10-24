package cmd

import (
	"context"
	"fmt"
	"time"
)

// doctorServiceChecks reports the background service (installed / active / healthy). It reports
// nothing when no service is installed, so doctor stays quiet for users who run dev by hand.
func doctorServiceChecks() []doctorResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := collectServiceReport(ctx, "nexus-cli")
	if err != nil || (!r.Installed && r.StateFile == nil) {
		return nil
	}
	out := []doctorResult{{true, fmt.Sprintf("service installed (%s: %s)", r.Platform, r.Definition)}}
	switch {
	case !r.Running:
		msg := "service not running (state: " + r.Status.State
		if r.StatusError != "" {
			msg += ", " + r.StatusError
		}
		out = append(out, doctorResult{false, msg + ") — run: nexus-cli service start; logs: nexus-cli service logs"})
	case !r.Health.OK:
		out = append(out, doctorResult{false, fmt.Sprintf("service running but proxy unhealthy at %s: %s", r.Health.URL, r.Health.Error)})
	default:
		out = append(out, doctorResult{true, fmt.Sprintf("service active and healthy at %s", r.Listen)})
	}
	if r.Running && r.Control == nil {
		out = append(out, doctorResult{false, "service dev process has no control endpoint in " + r.NexusHome + "/control — NEXUS_HOME differs from the service's, so 'approve' and 'run --attach' cannot see it"})
	}
	return out
}
