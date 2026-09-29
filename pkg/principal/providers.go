package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ProviderInfo describes a provider registered on the nexus-framework Gateway.
type ProviderInfo struct {
	Name        string
	AuthType    string // "oauth2" or "api_key"
	Category    string
	Description string
	Scopes      []string
}

// providerMeta is the per-provider shape returned by GET /v1/providers.
type providerMeta struct {
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
}

// ListProviders fetches the Gateway's public provider catalog, grouped by auth_type upstream and
// flattened here into a sorted list.
func ListProviders(ctx context.Context, gateway string) ([]ProviderInfo, error) {
	groups, err := fetchProviderCatalog(ctx, gateway)
	if err != nil {
		return nil, err
	}
	var out []ProviderInfo
	for authType, byName := range groups {
		for name, meta := range byName {
			out = append(out, ProviderInfo{
				Name:        name,
				AuthType:    authType,
				Category:    meta.Category,
				Description: meta.Description,
				Scopes:      meta.Scopes,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchProviderCatalog(ctx context.Context, gateway string) (map[string]map[string]providerMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(gateway, "/")+"/v1/providers", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider metadata: %s", resp.Status)
	}
	var groups map[string]map[string]providerMeta
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// fetchProviderScopes returns a single provider's registered default scopes.
func fetchProviderScopes(ctx context.Context, gateway, provider string) ([]string, error) {
	groups, err := fetchProviderCatalog(ctx, gateway)
	if err != nil {
		return nil, err
	}
	for _, byName := range groups {
		if pv, ok := byName[provider]; ok {
			return pv.Scopes, nil
		}
	}
	return nil, fmt.Errorf("provider %q not found in Gateway metadata", provider)
}
