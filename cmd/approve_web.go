package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
)

// openBrowser opens url in the default browser without a shell; tests replace it.
var openBrowser = func(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	if name == "" {
		return fmt.Errorf("don't know how to open a browser on %s", runtime.GOOS)
	}
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func browserCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		return "xdg-open", []string{url}
	}
	return "", nil
}

// pickWebEndpoint chooses the endpoint for --web: the one with --pid, the only one, or the one with
// the oldest pending request (falling back to the most recently started).
func pickWebEndpoint(ctx context.Context, infos []control.Info, pid int) (control.Info, error) {
	if len(infos) == 0 {
		return control.Info{}, errors.New("no running nexus-cli endpoints found (start `nexus-cli dev`, `run` or `mcp serve` first)")
	}
	if pid != 0 {
		for _, i := range infos {
			if i.PID == pid {
				return i, nil
			}
		}
		return control.Info{}, fmt.Errorf("no running endpoint with pid %d (running: %s)", pid, describeEndpoints(infos))
	}
	if len(infos) == 1 {
		return infos[0], nil
	}
	best := infos[len(infos)-1] // Discover sorts oldest first
	var oldest *endpointRequest
	for _, info := range infos {
		c := control.NewClient(info)
		reqs, err := c.List(ctx, 0)
		c.Close()
		if err != nil {
			continue
		}
		for _, r := range reqs {
			if oldest == nil || r.Created.Before(oldest.req.Created) {
				oldest = &endpointRequest{info, r}
			}
		}
	}
	if oldest != nil {
		best = oldest.info
	}
	return best, nil
}

func describeEndpoints(infos []control.Info) string {
	parts := make([]string, len(infos))
	for i, info := range infos {
		parts[i] = fmt.Sprintf("%s/%d", cell(info.Kind, 8), info.PID)
	}
	return strings.Join(parts, ", ")
}

func approveWeb(ctx context.Context, out io.Writer, pid int, open bool) error {
	infos, err := control.Discover()
	if err != nil {
		return err
	}
	info, err := pickWebEndpoint(ctx, infos, pid)
	if err != nil {
		return err
	}
	if len(infos) > 1 && pid == 0 {
		fmt.Fprintf(out, "note: %d endpoints running (%s); using %s/%d — choose with --pid\n",
			len(infos), describeEndpoints(infos), cell(info.Kind, 8), info.PID)
	}
	c := control.NewClient(info)
	defer c.Close()
	lc, err := c.LoginCode(ctx)
	if err != nil {
		return fmt.Errorf("mint login link: %w", err)
	}
	src := fmt.Sprintf("%s · pid %d", cell(info.Kind, 8), info.PID)
	if info.CWD != "" {
		src += " · " + cell(info.CWD, 80)
	}
	fmt.Fprintf(out, "Approvals web UI for %s\none-time login link (valid %s, single use):\n\n  %s\n\n", src, control.LoginCodeTTL, lc.URL)
	if !open {
		return nil
	}
	if err := openBrowser(lc.URL); err != nil {
		fmt.Fprintf(out, "could not open a browser (%v); open the link above manually\n", err)
		return nil
	}
	fmt.Fprintln(out, "opened in your browser")
	return nil
}
