package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// testIssuer is a minimal OIDC issuer that serves discovery and its JWKS, and signs tokens with its own key
type testIssuer struct {
	*httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ti := &testIssuer{key: key, kid: "test-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                ti.URL,
			"authorization_endpoint":                ti.URL + "/auth",
			"token_endpoint":                        ti.URL + "/token",
			"jwks_uri":                              ti.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: ti.kid, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})
	ti.Server = httptest.NewServer(mux)
	t.Cleanup(ti.Close)
	return ti
}

// token signs the claims, defaulting "iss" to the issuer URL, "exp" to five minutes from now and "iat" to now
func (ti *testIssuer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload := map[string]any{
		"iss": ti.URL,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		payload[k] = v
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: ti.key, KeyID: ti.kid},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	data, err := json.Marshal(payload)
	require.NoError(t, err)
	jws, err := signer.Sign(data)
	require.NoError(t, err)
	token, err := jws.CompactSerialize()
	require.NoError(t, err)
	return token
}
