package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/boring-registry/boring-registry/pkg/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDiscoveryServer serves only the OIDC discovery document, with absolute endpoint URLs
func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                s.URL,
			"authorization_endpoint":                s.URL + "/auth",
			"token_endpoint":                        s.URL + "/token",
			"jwks_uri":                              s.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(s.Close)
	return s
}

func resetAuthConfigFlags(t *testing.T) {
	t.Helper()
	flagAuthConfig, flagAuthConfigInline = "", ""
	t.Cleanup(func() { flagAuthConfig, flagAuthConfigInline = "", "" })
}

func TestLoadAuthConfig(t *testing.T) {
	valid := "version: 1\noidc:\n  - name: ci\n    issuer: https://issuer.example.com\n    audience: boring-registry\n"
	path := filepath.Join(t.TempDir(), "auth.yaml")
	require.NoError(t, os.WriteFile(path, []byte(valid), 0o600))
	missing := filepath.Join(t.TempDir(), "missing.yaml")

	tests := []struct {
		name      string
		file      string
		inline    string
		wantNil   bool
		wantCount int
		wantErr   string
	}{
		{name: "neither flag", wantNil: true},
		{name: "file", file: path, wantCount: 1},
		{name: "inline", inline: valid, wantCount: 1},
		{name: "both", file: path, inline: valid, wantErr: "mutually exclusive"},
		{name: "missing file", file: missing, wantErr: missing},
		{name: "invalid yaml", inline: "version: [", wantErr: "auth config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetAuthConfigFlags(t)
			flagAuthConfig, flagAuthConfigInline = tt.file, tt.inline

			cfg, err := loadAuthConfig()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, cfg)
				return
			}
			assert.Len(t, cfg.OIDC, tt.wantCount)
		})
	}
}

func TestSetupOidcIssuers(t *testing.T) {
	s := newDiscoveryServer(t)

	t.Run("login issuer and accept-only issuer", func(t *testing.T) {
		cfg := mustParseAuthConfig(t, fmt.Sprintf(`version: 1
oidc:
  - name: people
    issuer: %[1]s
    audience: api-app
    login:
      client_id: cli
      scopes: [openid]
      auth_url: https://override/authz
  - name: ci
    issuer: %[1]s
    audience: boring-registry
    claims:
      repository_owner: [frasers-org]
`, s.URL))

		providers, login, err := setupOidcIssuers(context.Background(), cfg)
		require.NoError(t, err)
		require.Len(t, providers, 2)
		assert.Equal(t, "people", providers[0].String())
		assert.Equal(t, "ci", providers[1].String())
		require.NotNil(t, login)
		assert.Equal(t, "cli", login.Client)
		assert.Equal(t, "https://override/authz", login.Authz)
		assert.Equal(t, s.URL+"/token", login.Token)
		assert.Equal(t, []string{"openid"}, login.Scopes)
		assert.Equal(t, flagLoginGrantTypes, login.GrantTypes)
		assert.Equal(t, flagLoginPorts, login.Ports)
	})

	t.Run("auth url from discovery", func(t *testing.T) {
		cfg := mustParseAuthConfig(t, fmt.Sprintf("version: 1\noidc:\n  - name: people\n    issuer: %s\n    audience: api-app\n    login:\n      client_id: cli\n", s.URL))
		_, login, err := setupOidcIssuers(context.Background(), cfg)
		require.NoError(t, err)
		require.NotNil(t, login)
		assert.Equal(t, s.URL+"/auth", login.Authz)
	})

	t.Run("no login issuer", func(t *testing.T) {
		cfg := mustParseAuthConfig(t, fmt.Sprintf("version: 1\noidc:\n  - name: ci\n    issuer: %s\n    audience: boring-registry\n", s.URL))
		providers, login, err := setupOidcIssuers(context.Background(), cfg)
		require.NoError(t, err)
		assert.Len(t, providers, 1)
		assert.Nil(t, login)
	})

	t.Run("unreachable issuer", func(t *testing.T) {
		cfg := mustParseAuthConfig(t, "version: 1\noidc:\n  - name: unreachable\n    issuer: http://127.0.0.1:1\n    audience: boring-registry\n")
		_, _, err := setupOidcIssuers(context.Background(), cfg)
		assert.ErrorContains(t, err, "unreachable")
	})
}

func mustParseAuthConfig(t *testing.T, config string) *auth.Config {
	t.Helper()
	cfg, err := auth.ParseConfig([]byte(config))
	require.NoError(t, err)
	return cfg
}
