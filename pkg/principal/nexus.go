package principal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	oauthsdk "github.com/Prescott-Data/nexus-framework/nexus-sdk"
)

// DefaultGatewayURL is the local nexus-framework Gateway address.
const DefaultGatewayURL = "http://localhost:8090"

// NexusProvider authenticates the human through the nexus-framework Gateway
type NexusProvider struct {
	GatewayURL     string
	ProviderName   string        // registered provider: github, slack, google, ...
	UserID         string        // the ID the Gateway associates this connection with
	ProviderScopes []string      // OAuth scopes to request from the provider (optional)
	Ceiling        []string      // nexus scope ceiling recorded on the principal
	ReturnURL      string        // optional post-consent redirect for the human's browser
	TTL            time.Duration // how long the resulting principal is trusted
	PollInterval   time.Duration
	Prompt         func(url string)
}

// Name identifies the provider.
func (p NexusProvider) Name() string { return "nexus:" + p.ProviderName }

// Login brokers consent through the Gateway and resolves the human's identity.
func (p NexusProvider) Login(ctx context.Context) (*Principal, error) {
	res, err := Connect(ctx, ConnectOptions{
		GatewayURL:     p.GatewayURL,
		ProviderName:   p.ProviderName,
		UserID:         p.UserID,
		ProviderScopes: p.ProviderScopes,
		ReturnURL:      p.ReturnURL,
		PollInterval:   p.PollInterval,
		Prompt:         p.Prompt,
	})
	if err != nil {
		return nil, err
	}

	ttl := p.TTL
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	subject, email := identityFromToken(res.Token)
	if subject == "" {
		subject = p.UserID
	}
	if subject == "" {
		subject = "nexus:" + res.ConnectionID
	}
	prin := &Principal{
		Subject:      subject,
		Email:        email,
		Issuer:       "nexus:" + p.ProviderName,
		Scopes:       p.Ceiling,
		ExpiresAt:    time.Now().Add(ttl),
		GatewayURL:   res.GatewayURL,
		ConnectionID: res.ConnectionID,
	}
	prin.AddConnection(res.Connection())
	return prin, nil
}

// ConnectOptions configures a single broker-connection handshake.
type ConnectOptions struct {
	GatewayURL     string
	ProviderName   string
	UserID         string
	ProviderScopes []string
	ReturnURL      string
	PollInterval   time.Duration
	Prompt         func(url string)
}

// ConnectResult is the outcome of a successful broker-connection handshake.
type ConnectResult struct {
	Provider     string
	ConnectionID string
	GatewayURL   string
	Scopes       []string
	Token        *oauthsdk.TokenResponse
}

// Connection converts the result into a stored Connection record.
func (r *ConnectResult) Connection() Connection {
	return Connection{
		Provider:     r.Provider,
		ConnectionID: r.ConnectionID,
		GatewayURL:   r.GatewayURL,
		Scopes:       r.Scopes,
		CreatedAt:    time.Now(),
	}
}

// Connect brokers a single provider connection through the Gateway
func Connect(ctx context.Context, opts ConnectOptions) (*ConnectResult, error) {
	if opts.ProviderName == "" {
		return nil, fmt.Errorf("nexus: provider name is required")
	}
	gateway := opts.GatewayURL
	if gateway == "" {
		gateway = DefaultGatewayURL
	}
	prompt := opts.Prompt
	if prompt == nil {
		prompt = func(u string) {
			fmt.Fprintf(os.Stderr, "\nOpen this URL to authorize with %s:\n%s\n\n", opts.ProviderName, u)
		}
	}
	interval := opts.PollInterval
	if interval <= 0 {
		interval = 1500 * time.Millisecond
	}

	// gateway requires a return_url to redirect the human's browser to after consent
	returnURL := opts.ReturnURL
	var landed <-chan struct{}
	if returnURL == "" {
		url, hit, shutdown, lerr := newLandingServer()
		if lerr != nil {
			return nil, fmt.Errorf("nexus: start loopback landing server: %w", lerr)
		}
		defer shutdown()
		returnURL = url
		landed = hit
	}

	client := oauthsdk.New(gateway)

	// gateway does not inject a provider's registered default scopes into the authorize URL,
	// so an empty scope list yields scope=&… and the provider rejects the handshake
	scopes := opts.ProviderScopes
	if len(scopes) == 0 {
		if def, derr := fetchProviderScopes(ctx, gateway, opts.ProviderName); derr == nil && len(def) > 0 {
			scopes = def
			fmt.Fprintf(os.Stderr, "Using %d default scope(s) registered for %q on the Gateway.\n", len(scopes), opts.ProviderName)
		}
	}

	conn, err := client.RequestConnection(ctx, oauthsdk.RequestConnectionInput{
		UserID:       opts.UserID,
		ProviderName: opts.ProviderName,
		Scopes:       scopes,
		ReturnURL:    returnURL,
	})
	if err != nil {
		return nil, fmt.Errorf("nexus: request connection: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Connection %s created for provider %q.\n", conn.ConnectionID, opts.ProviderName)
	prompt(conn.AuthURL)
	openBrowser(conn.AuthURL)

	fmt.Fprintln(os.Stderr, "Waiting for you to authorize in the browser… (the status may read \"failed\" until you finish consent — that's expected)")
	status, err := waitForConnection(ctx, client, conn.ConnectionID, interval)
	if err != nil {
		return nil, fmt.Errorf("nexus: waiting for consent: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Authorization received (status: %s); finalizing…\n", status)

	token, err := client.GetToken(ctx, conn.ConnectionID)
	if err != nil {
		return nil, fmt.Errorf("nexus: fetch token: %w", err)
	}

	// Keep the loopback landing page up until the browser follows the post-consent redirect, or a
	// grace period elapses.
	if landed != nil {
		select {
		case <-landed:
		case <-time.After(45 * time.Second):
		case <-ctx.Done():
		}
	}

	return &ConnectResult{
		Provider:     opts.ProviderName,
		ConnectionID: conn.ConnectionID,
		GatewayURL:   gateway,
		Scopes:       scopes,
		Token:        token,
	}, nil
}

// landingPageHTML is served on the loopback address the Gateway redirects to after consent.
const landingPageHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Nexus</title></head>
<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:5rem;color:#111">
<h1>✅ Authorized with Nexus</h1>
<p>You can close this window and return to the terminal.</p>
</body></html>`

// newLandingServer starts a loopback HTTP server that serves a success page for the Gateway's
// post-consent redirect
func newLandingServer() (url string, landed <-chan struct{}, shutdown func(), err error) {
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		return "", nil, nil, lerr
	}
	hit := make(chan struct{}, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, landingPageHTML)
		select {
		case hit <- struct{}{}:
		default:
		}
	})}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String() + "/", hit, func() { _ = srv.Shutdown(context.Background()) }, nil
}

// waitForConnection polls the Gateway until the connection reaches a success state or the context expires
func waitForConnection(ctx context.Context, client *oauthsdk.Client, connID string, interval time.Duration) (string, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := ""
	for {
		status, err := client.CheckConnection(ctx, connID)
		if err != nil {
			return "", err
		}
		if status != last {
			fmt.Fprintf(os.Stderr, "  connection status: %s\n", status)
			last = status
		}
		switch strings.ToLower(strings.TrimSpace(status)) {
		case "active", "success", "connected", "authorized", "completed", "ready":
			return status, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timed out waiting for authorization (last status: %s)", last)
		case <-ticker.C:
		}
	}
}

// IsActiveStatus reports whether a Gateway connection status means the connection is usable
func IsActiveStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active", "success", "connected", "authorized", "completed", "ready":
		return true
	}
	return false
}

// PendingConnection is a connection whose consent the human has not yet completed.
type PendingConnection struct {
	Provider     string
	ConnectionID string
	GatewayURL   string
	AuthURL      string
	Scopes       []string
}

// StartConnection requests a broker connection and returns the consent URL without waiting
func StartConnection(ctx context.Context, opts ConnectOptions) (*PendingConnection, error) {
	if opts.ProviderName == "" {
		return nil, fmt.Errorf("nexus: provider name is required")
	}
	gateway := opts.GatewayURL
	if gateway == "" {
		gateway = DefaultGatewayURL
	}
	scopes := opts.ProviderScopes
	if len(scopes) == 0 {
		if def, derr := fetchProviderScopes(ctx, gateway, opts.ProviderName); derr == nil {
			scopes = def
		}
	}
	conn, err := oauthsdk.New(gateway).RequestConnection(ctx, oauthsdk.RequestConnectionInput{
		UserID:       opts.UserID,
		ProviderName: opts.ProviderName,
		Scopes:       scopes,
		ReturnURL:    opts.ReturnURL,
	})
	if err != nil {
		return nil, fmt.Errorf("nexus: request connection: %w", err)
	}
	return &PendingConnection{
		Provider:     opts.ProviderName,
		ConnectionID: conn.ConnectionID,
		GatewayURL:   gateway,
		AuthURL:      conn.AuthURL,
		Scopes:       scopes,
	}, nil
}

// CheckStatus returns the raw Gateway status for a connection.
func CheckStatus(ctx context.Context, gateway, connID string) (string, error) {
	return oauthsdk.New(gateway).CheckConnection(ctx, connID)
}

// FetchToken returns a short-lived access token for a connection
func FetchToken(ctx context.Context, gateway, connID string) (string, error) {
	t, err := oauthsdk.New(gateway).GetToken(ctx, connID)
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

// ReturnURLServer starts a persistent loopback landing page for post-consent redirects and returns
// its URL plus a shutdown func
func ReturnURLServer() (url string, shutdown func(), err error) {
	u, _, sd, e := newLandingServer()
	return u, sd, e
}

// identityFromToken extracts email/subject from the Gateway-issued id_token
func identityFromToken(token *oauthsdk.TokenResponse) (subject, email string) {
	if token == nil || token.IDToken == nil || *token.IDToken == "" {
		return "", ""
	}
	parts := strings.Split(*token.IDToken, ".")
	if len(parts) != 3 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ""
	}
	subject = claims.Email
	if subject == "" {
		subject = claims.PreferredUsername
	}
	if subject == "" {
		subject = claims.Sub
	}
	return subject, claims.Email
}
