package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/boring-registry/boring-registry/pkg/core"

	"github.com/go-kit/kit/auth/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware(t *testing.T) {
	t.Parallel()

	type providerCase struct {
		name      string
		providers []Provider
		ctx       context.Context
		wantError bool
	}

	testCases := []providerCase{
		{
			name:      "token matches single provider",
			providers: []Provider{NewStaticProvider("foo")},
			ctx:       context.WithValue(context.Background(), jwt.JWTContextKey, "foo"),
			wantError: false,
		},
		{
			name:      "token matches first provider",
			providers: []Provider{NewStaticProvider("foo"), NewStaticProvider("bar")},
			ctx:       context.WithValue(context.Background(), jwt.JWTContextKey, "foo"),
			wantError: false,
		},
		{
			name:      "token matches second provider",
			providers: []Provider{NewStaticProvider("foo"), NewStaticProvider("bar")},
			ctx:       context.WithValue(context.Background(), jwt.JWTContextKey, "bar"),
			wantError: false,
		},
		{
			name:      "token matches none",
			providers: []Provider{NewStaticProvider("foo"), NewStaticProvider("bar")},
			ctx:       context.WithValue(context.Background(), jwt.JWTContextKey, "baz"),
			wantError: true,
		},
		{
			name:      "no token in context",
			providers: []Provider{NewStaticProvider("foo"), NewStaticProvider("bar")},
			ctx:       context.Background(),
			wantError: true,
		},
		{
			name:      "token key is set but empty",
			providers: []Provider{NewStaticProvider("foo")},
			ctx:       context.WithValue(context.Background(), jwt.JWTContextKey, ""),
			wantError: true,
		},
		{
			name:      "no providers, should skip auth",
			providers: []Provider{},
			ctx:       context.WithValue(context.Background(), jwt.JWTContextKey, "anything"),
			wantError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Middleware(tc.providers...)(nopEndpoint)(tc.ctx, nil)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func nopEndpoint(ctx context.Context, request any) (any, error) {
	return true, nil
}

func TestMiddlewareMultipleIssuers(t *testing.T) {
	entraIssuer := newTestIssuer(t)
	githubIssuer := newTestIssuer(t)

	entra, err := NewOidcProvider(context.Background(), entraIssuer.URL, "", "api-app", WithName("entra"), WithClaimRules(ClaimRules{"roles": {"Registry.Read"}}))
	require.NoError(t, err)
	github, err := NewOidcProvider(context.Background(), githubIssuer.URL, "", "boring-registry", WithName("github-actions"), WithClaimRules(ClaimRules{"repository_owner": {"frasers-org"}}))
	require.NoError(t, err)

	mw := Middleware(NewStaticProvider("static-token"), entra, github)
	endpoint := mw(func(ctx context.Context, request any) (any, error) { return "ok", nil })

	tests := []struct {
		name       string
		token      string
		authorized bool
	}{
		{"static token", "static-token", true},
		{"entra token with role", entraIssuer.token(t, map[string]any{"aud": "api-app", "roles": []string{"Registry.Read"}}), true},
		{"github token from org", githubIssuer.token(t, map[string]any{"aud": "boring-registry", "repository_owner": "frasers-org"}), true},
		{"github token from another org", githubIssuer.token(t, map[string]any{"aud": "boring-registry", "repository_owner": "evil-org"}), false},
		{"entra token for github audience", entraIssuer.token(t, map[string]any{"aud": "boring-registry"}), false},
		{"entra token without role but github claims", entraIssuer.token(t, map[string]any{"aud": "api-app", "repository_owner": "frasers-org"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := endpoint(context.WithValue(context.Background(), jwt.JWTContextKey, tt.token), nil)
			if tt.authorized {
				assert.NoError(t, err)
				assert.Equal(t, "ok", resp)
			} else {
				assert.True(t, errors.Is(err, core.ErrUnauthorized), "expected ErrUnauthorized, got %v", err)
			}
		})
	}
}
