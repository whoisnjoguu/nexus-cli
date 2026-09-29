package principal

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLandingServerServesSuccessPage(t *testing.T) {
	url, landed, shutdown, err := newLandingServer()
	if err != nil {
		t.Fatal(err)
	}
	defer shutdown()

	resp, err := http.Get(url + "?connection_id=abc&status=success")
	if err != nil {
		t.Fatalf("landing page unreachable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorized with Nexus") {
		t.Fatalf("unexpected body: %q", string(body))
	}
	select {
	case <-landed:
	case <-time.After(time.Second):
		t.Fatal("landed signal not fired after a request")
	}
}
