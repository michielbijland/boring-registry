package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/boring-registry/boring-registry/pkg/auth"
	"github.com/boring-registry/boring-registry/pkg/discovery"
)

// loadAuthConfig returns nil, nil when neither --auth-config nor --auth-config-inline is set
func loadAuthConfig() (*auth.Config, error) {
	if flagAuthConfig != "" && flagAuthConfigInline != "" {
		return nil, errors.New("--auth-config and --auth-config-inline are mutually exclusive")
	}

	var data []byte
	switch {
	case flagAuthConfig != "":
		var err error
		data, err = os.ReadFile(flagAuthConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to read auth config %s: %w", flagAuthConfig, err)
		}
	case flagAuthConfigInline != "":
		data = []byte(flagAuthConfigInline)
	default:
		return nil, nil
	}

	return auth.ParseConfig(data)
}

// setupOidcIssuers creates one provider per config issuer, login is non-nil only for the issuer with `login`
func setupOidcIssuers(ctx context.Context, cfg *auth.Config) ([]auth.Provider, *discovery.LoginV1, error) {
	authCtx, cancelAuthCtx := context.WithTimeout(ctx, 15*time.Second)
	defer cancelAuthCtx()

	providers := []auth.Provider{}
	var login *discovery.LoginV1
	for _, ic := range cfg.OIDC {
		clientID := ""
		if ic.Login != nil {
			clientID = ic.Login.ClientID
		}

		p, err := auth.NewOidcProvider(authCtx, ic.Issuer, clientID, ic.Audience, auth.WithName(ic.Name), auth.WithClaimRules(ic.Claims))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to set up oidc issuer %q: %w", ic.Name, err)
		}
		providers = append(providers, p)

		slog.Info("configured oidc issuer",
			slog.String("name", ic.Name),
			slog.String("issuer", ic.Issuer),
			slog.Bool("login", ic.Login != nil),
			slog.Int("claims", len(ic.Claims)),
		)
		if len(ic.Claims) == 0 {
			slog.Warn("oidc issuer has no claim rules, any token from this issuer for the audience is accepted",
				slog.String("name", ic.Name),
				slog.String("issuer", ic.Issuer),
			)
		}

		if ic.Login != nil {
			authURL := p.AuthURL()
			if ic.Login.AuthURL != "" {
				// Allow overriding the authURL to allow customization, e.g. setting additional query params
				authURL = ic.Login.AuthURL
			}
			login = &discovery.LoginV1{
				Client:     ic.Login.ClientID,
				GrantTypes: flagLoginGrantTypes,
				Authz:      authURL,
				Token:      p.TokenURL(),
				Ports:      flagLoginPorts,
				Scopes:     ic.Login.Scopes,
			}
		}
	}

	return providers, login, nil
}
