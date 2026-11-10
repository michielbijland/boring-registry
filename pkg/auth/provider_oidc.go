package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OidcProvider struct {
	logger           *slog.Logger
	issuer           string
	clientIdentifier string
	audience         string
	name             string
	claimRules       ClaimRules
	provider         *oidc.Provider
}

// OidcOption configures optional OidcProvider settings
type OidcOption func(*OidcProvider)

// WithName sets the provider name used in logs, it defaults to "oidc"
func WithName(name string) OidcOption {
	return func(o *OidcProvider) {
		o.name = name
	}
}

// WithClaimRules sets the claim rules a verified token must also satisfy
func WithClaimRules(rules ClaimRules) OidcOption {
	return func(o *OidcProvider) {
		o.claimRules = rules
	}
}

func (o *OidcProvider) String() string { return o.name }

// Issuer returns the issuer URL
func (o *OidcProvider) Issuer() string { return o.issuer }

// Verify checks the token's signature, expiry, issuer, and audience, and then the claim rules
func (o *OidcProvider) Verify(ctx context.Context, token string) error {
	// The go-oidc library uses Config.ClientID to verify the "aud" claim in the JWT.
	// Some identity providers (e.g. Okta without API Access Management) issue tokens where "aud" doesn't match the OIDC client ID.
	// When an explicit audience is configured, we use it instead of the client ID for audience verification.
	expectedAudience := o.clientIdentifier
	if o.audience != "" {
		expectedAudience = o.audience
	}

	oidcConfig := &oidc.Config{
		ClientID: expectedAudience,
	}
	verifier := o.provider.VerifierContext(ctx, oidcConfig)

	// Check method documentation to see what is verified and what not.
	// The returned IdToken can be used to verify claims.
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return err
	}

	if len(o.claimRules) == 0 {
		return nil
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to decode token claims: %w", err)
	}
	if err := o.claimRules.Match(claims); err != nil {
		return fmt.Errorf("claim rules not satisfied: %w", err)
	}
	return nil
}

func (o *OidcProvider) AuthURL() string {
	return o.provider.Endpoint().AuthURL
}

func (o *OidcProvider) TokenURL() string {
	return o.provider.Endpoint().TokenURL
}

func NewOidcProvider(ctx context.Context, issuer, clientIdentifier, audience string, opts ...OidcOption) (*OidcProvider, error) {
	logger := slog.Default()
	start := time.Now()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	logger.Info("finished initializing OIDC provider", slog.String("took", time.Since(start).String()))

	o := &OidcProvider{
		logger:           logger,
		issuer:           issuer,
		clientIdentifier: clientIdentifier,
		audience:         audience,
		name:             "oidc",
		provider:         provider,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o, nil
}
