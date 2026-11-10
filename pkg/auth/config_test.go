package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validConfig = `version: 1
oidc:
  - name: entra
    issuer: https://login.microsoftonline.com/tenant/v2.0
    audience: api-app
    login:
      client_id: cli-app
      scopes: ["api://api-app/registry.read", "openid"]
    claims:
      roles: ["Registry.Read"]
  - name: github-actions
    issuer: https://token.actions.githubusercontent.com
    audience: boring-registry
    claims:
      repository_owner: ["frasers-org"]
`

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	require.NoError(t, err)
	require.Len(t, cfg.OIDC, 2)
	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "entra", cfg.OIDC[0].Name)
	assert.Equal(t, "cli-app", cfg.OIDC[0].Login.ClientID)
	assert.Equal(t, []string{"api://api-app/registry.read", "openid"}, cfg.OIDC[0].Login.Scopes)
	assert.Nil(t, cfg.OIDC[1].Login)
	assert.Equal(t, []string{"frasers-org"}, cfg.OIDC[1].Claims["repository_owner"])

	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{"missing version", strings.Replace(validConfig, "version: 1\n", "", 1), "version"},
		{"wrong version", strings.Replace(validConfig, "version: 1", "version: 2", 1), "version"},
		{"unknown top-level key", validConfig + "access: []\n", "access"},
		{"unknown issuer key", strings.Replace(validConfig, "    audience: boring-registry\n", "    audience: boring-registry\n    namespaces: [x]\n", 1), "namespaces"},
		{"missing name", strings.Replace(validConfig, "  - name: github-actions\n    issuer", "  - issuer", 1), "name"},
		{"missing issuer", strings.Replace(validConfig, "    issuer: https://token.actions.githubusercontent.com\n", "", 1), "issuer"},
		{"missing audience", strings.Replace(validConfig, "    audience: boring-registry\n", "", 1), "audience"},
		{"duplicate name", strings.Replace(validConfig, "name: github-actions", "name: entra", 1), "duplicate"},
		{"two logins", strings.Replace(validConfig, "    audience: boring-registry\n", "    audience: boring-registry\n    login:\n      client_id: other\n", 1), "login"},
		{"login without client_id", strings.Replace(validConfig, "      client_id: cli-app\n", "", 1), "client_id"},
		{"empty pattern list", strings.Replace(validConfig, `repository_owner: ["frasers-org"]`, "repository_owner: []", 1), "repository_owner"},
		{"empty pattern string", strings.Replace(validConfig, `repository_owner: ["frasers-org"]`, `repository_owner: [""]`, 1), "repository_owner"},
		{"scalar pattern rejected", strings.Replace(validConfig, `repository_owner: ["frasers-org"]`, "repository_owner: frasers-org", 1), "repository_owner"},
		{"empty document", "", "version"},
		{"null claims", strings.Replace(validConfig, "    claims:\n      repository_owner: [\"frasers-org\"]\n", "    claims:\n", 1), "claims"},
		{"tilde claims", strings.Replace(validConfig, "    claims:\n      repository_owner: [\"frasers-org\"]\n", "    claims: ~\n", 1), "claims"},
		{"empty claims mapping", strings.Replace(validConfig, "    claims:\n      repository_owner: [\"frasers-org\"]\n", "    claims: {}\n", 1), "claims"},
		{"no issuers", "version: 1\n", "oidc"},
		{"empty issuer list", "version: 1\noidc: []\n", "oidc"},
		{"alias to null claims", strings.Replace(strings.Replace(validConfig, "      client_id: cli-app\n", "      client_id: cli-app\n      auth_url: &n\n", 1), "    claims:\n      repository_owner: [\"frasers-org\"]\n", "    claims: *n\n", 1), "claims"},
		{"duplicate claim key", strings.Replace(validConfig, `repository_owner: ["frasers-org"]`, "repository_owner: [\"frasers-org\"]\n      repository_owner: [\"*\"]", 1), "repository_owner"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.config))
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParseConfigWithoutClaims(t *testing.T) {
	// Leaving out the claims key is the explicit opt-out of claim rules
	cfg, err := ParseConfig([]byte("version: 1\noidc:\n  - name: ci\n    issuer: https://issuer.example.com\n    audience: boring-registry\n"))
	require.NoError(t, err)
	assert.Empty(t, cfg.OIDC[0].Claims)
}
