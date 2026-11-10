package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware(t *testing.T) {
	data := `{
				"issuer": "ISSUER",
				"authorization_endpoint": "/auth",
				"token_endpoint": "/token",
				"jwks_uri": "/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`

	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.ReplaceAll(data, "ISSUER", flagAuthOidcIssuer))
	}
	s := httptest.NewServer(http.HandlerFunc(hf))
	defer s.Close()

	// A separate issuer for the auth config, its discovery document doesn't depend on the legacy flags
	configIssuer := newDiscoveryServer(t)
	configWithLogin := fmt.Sprintf("version: 1\noidc:\n  - name: people\n    issuer: %s\n    audience: api-app\n    login:\n      client_id: config-cli\n", configIssuer.URL)
	configWithoutLogin := fmt.Sprintf("version: 1\noidc:\n  - name: ci\n    issuer: %s\n    audience: boring-registry\n    claims:\n      repository_owner: [frasers-org]\n", configIssuer.URL)
	configNamedOidc := fmt.Sprintf("version: 1\noidc:\n  - name: oidc\n    issuer: %s\n    audience: boring-registry\n", configIssuer.URL)

	tests := []struct {
		name             string
		authOidcIssuer   string
		authOidcClientId string
		authOktaIssuer   string
		authOktaClientId string
		authOktaAuthz    string
		authOktaToken    string
		authConfigInline string
		wantErr          bool
		errMessage       string
	}{
		{
			name:             "only OIDC is configured",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
		},
		{
			name:             "OIDC and Okta are both configured",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
			authOktaIssuer:   "something",
			wantErr:          true,
			errMessage:       "both OIDC and Okta are configured, only one is allowed at a time",
		},
		{
			name:             "Okta is configured",
			authOktaIssuer:   "something",
			authOktaClientId: "boring-registry",
			authOktaAuthz:    "/authz",
			authOktaToken:    "/token",
		},
		{
			name:             "auth config issuer with login",
			authConfigInline: configWithLogin,
		},
		{
			name:             "auth config issuer without login and legacy OIDC",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
			authConfigInline: configWithoutLogin,
		},
		{
			name:             "legacy OIDC and auth config issuer with login",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
			authConfigInline: configWithLogin,
			wantErr:          true,
			errMessage:       "login.v1",
		},
		{
			name:             "Okta and auth config issuer with login",
			authOktaIssuer:   "something",
			authOktaClientId: "boring-registry",
			authOktaAuthz:    "/authz",
			authOktaToken:    "/token",
			authConfigInline: configWithLogin,
			wantErr:          true,
			errMessage:       "login.v1",
		},
		{
			name:             "auth config issuer named oidc and legacy OIDC",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
			authConfigInline: configNamedOidc,
			wantErr:          true,
			errMessage:       "duplicate",
		},
	}

	for _, test := range tests {
		// Initializing global variables, this is potentially problematic!
		flagAuthOidcIssuer = test.authOidcIssuer
		flagAuthOidcClientId = test.authOidcClientId
		flagAuthOktaIssuer = test.authOktaIssuer
		flagAuthOktaClientId = test.authOktaClientId
		flagAuthOktaAuthz = test.authOktaAuthz
		flagAuthOktaToken = test.authOktaToken
		flagAuthConfig = ""
		flagAuthConfigInline = test.authConfigInline

		mw, login, err := authMiddleware(context.Background())
		if test.wantErr {
			assert.Error(t, err, test.name)
			assert.ErrorContains(t, err, test.errMessage, test.name)
		} else {
			assert.NoError(t, err, test.name)
			if assert.NotNil(t, login, test.name) {
				if test.authOidcIssuer != "" {
					assert.Equal(t, test.authOidcClientId, login.Client, test.name)
				} else if test.authOktaIssuer != "" {
					assert.Equal(t, test.authOktaClientId, login.Client, test.name)
				} else if test.authConfigInline != "" {
					assert.Equal(t, "config-cli", login.Client, test.name)
				}
				assert.NotEmpty(t, login.Authz)
				assert.NotEmpty(t, login.Token)
				assert.NotEmpty(t, login.GrantTypes)
				assert.NotEmpty(t, login.Ports)
			}
			assert.NotNil(t, mw)
		}
	}
	flagAuthOidcIssuer, flagAuthOidcClientId, flagAuthOktaIssuer, flagAuthOktaClientId = "", "", "", ""
	flagAuthOktaAuthz, flagAuthOktaToken, flagAuthConfigInline = "", "", ""
}
