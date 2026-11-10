package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOidcProviderDiscovery(t *testing.T) {
	data := `{
				"issuer": "ISSUER",
				"authorization_endpoint": "/auth",
				"token_endpoint": "/token",
				"jwks_uri": "/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`

	var issuer string
	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, strings.ReplaceAll(data, "ISSUER", issuer)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}
	s := httptest.NewServer(http.HandlerFunc(hf))
	defer s.Close()
	issuer = s.URL

	provider, err := NewOidcProvider(context.Background(), issuer, "boring-registry", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, provider.AuthURL())
	assert.NotEmpty(t, provider.TokenURL())
}

func TestOidcProviderVerify(t *testing.T) {
	ti := newTestIssuer(t)
	other := newTestIssuer(t)
	rules := ClaimRules{"repository_owner": {"frasers-org"}}
	p, err := NewOidcProvider(context.Background(), ti.URL, "", "boring-registry", WithName("github-actions"), WithClaimRules(rules))
	require.NoError(t, err)
	assert.Equal(t, "github-actions", p.String())
	assert.Equal(t, ti.URL, p.Issuer())

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"valid token and claims", ti.token(t, map[string]any{"aud": "boring-registry", "repository_owner": "frasers-org"}), false},
		{"aud as array", ti.token(t, map[string]any{"aud": []string{"other", "boring-registry"}, "repository_owner": "frasers-org"}), false},
		{"wrong audience", ti.token(t, map[string]any{"aud": "https://github.com/frasers-org", "repository_owner": "frasers-org"}), true},
		{"claim rule fails", ti.token(t, map[string]any{"aud": "boring-registry", "repository_owner": "evil-org"}), true},
		{"claim missing", ti.token(t, map[string]any{"aud": "boring-registry"}), true},
		{"expired", ti.token(t, map[string]any{"aud": "boring-registry", "repository_owner": "frasers-org", "exp": time.Now().Add(-time.Minute).Unix()}), true},
		{"signed by another issuer key", other.token(t, map[string]any{"iss": ti.URL, "aud": "boring-registry", "repository_owner": "frasers-org"}), true},
		{"not a JWT", "static-token-value", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Verify(context.Background(), tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOidcProviderDefaultName(t *testing.T) {
	ti := newTestIssuer(t)
	p, err := NewOidcProvider(context.Background(), ti.URL, "boring-registry", "")
	require.NoError(t, err)
	assert.Equal(t, "oidc", p.String())
	// Without claim rules any valid token for the audience, which defaults to the client id, is accepted
	assert.NoError(t, p.Verify(context.Background(), ti.token(t, map[string]any{"aud": "boring-registry"})))
}
