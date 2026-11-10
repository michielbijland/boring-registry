package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Config is the auth config loaded with --auth-config or --auth-config-inline
type Config struct {
	Version int                `yaml:"version"`
	OIDC    []OidcIssuerConfig `yaml:"oidc"`
}

// OidcIssuerConfig configures an OIDC issuer whose tokens are accepted
type OidcIssuerConfig struct {
	Name     string           `yaml:"name"`
	Issuer   string           `yaml:"issuer"`
	Audience string           `yaml:"audience"`
	Login    *OidcLoginConfig `yaml:"login"`
	Claims   ClaimRules       `yaml:"claims"`
}

// OidcLoginConfig makes an issuer the one advertised in login.v1 for `terraform login`
type OidcLoginConfig struct {
	ClientID string   `yaml:"client_id"`
	Scopes   []string `yaml:"scopes"`
	AuthURL  string   `yaml:"auth_url"`
}

// UnmarshalYAML requires every claim to hold a list of patterns, so a scalar such as `repository_owner: org` is an error naming the claim
func (r *ClaimRules) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: claims must be a mapping of claim names to lists of patterns", node.Line)
	}

	rules := ClaimRules{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name, value := node.Content[i].Value, node.Content[i+1]
		if _, ok := rules[name]; ok {
			return fmt.Errorf("line %d: claims.%s is defined more than once", node.Content[i].Line, name)
		}
		if value.Kind != yaml.SequenceNode {
			return fmt.Errorf("line %d: claims.%s must be a list of patterns", value.Line, name)
		}
		var patterns []string
		if err := value.Decode(&patterns); err != nil {
			return fmt.Errorf("line %d: claims.%s: %w", value.Line, name, err)
		}
		rules[name] = patterns
	}
	*r = rules
	return nil
}

// ParseConfig strictly decodes the YAML auth config, rejecting unknown keys, and validates it
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to parse auth config: %w", err)
	}

	err := errors.Join(cfg.Validate(), checkEmptyClaims(data))
	if err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}
	return cfg, nil
}

// checkEmptyClaims rejects a claims key that is present but null or empty.
// The decoded struct can't tell it apart from a left-out key, which is the explicit opt-out of claim rules,
// and an empty key is most likely a mistake that would accept any token from the issuer.
func checkEmptyClaims(data []byte) error {
	var doc struct {
		OIDC []map[string]yaml.Node `yaml:"oidc"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// The strict decode already reported the problem
		return nil
	}

	var err error
	for i, ic := range doc.OIDC {
		claims, ok := ic["claims"]
		if !ok {
			continue
		}
		// Follow aliases, `claims: *anchor` must not hide an empty or null value
		for claims.Kind == yaml.AliasNode && claims.Alias != nil {
			claims = *claims.Alias
		}
		if claims.Kind == yaml.ScalarNode && claims.Tag == "!!null" || claims.Kind == yaml.MappingNode && len(claims.Content) == 0 {
			err = errors.Join(err, fmt.Errorf("oidc[%d]: claims is empty, leave out the key to accept any token from this issuer", i))
		}
	}
	return err
}

// Validate returns all problems with the config joined into one error
func (c *Config) Validate() error {
	var err error
	if c.Version != 1 {
		err = errors.Join(err, fmt.Errorf("version: must be 1, got %d", c.Version))
	}

	if len(c.OIDC) == 0 {
		err = errors.Join(err, errors.New("oidc: at least one issuer is required"))
	}

	names := map[string]bool{}
	logins := 0
	for i, ic := range c.OIDC {
		prefix := fmt.Sprintf("oidc[%d]", i)
		if ic.Name != "" {
			prefix = fmt.Sprintf("oidc[%d] (%s)", i, ic.Name)
		}

		if ic.Name == "" {
			err = errors.Join(err, fmt.Errorf("%s: name is required", prefix))
		} else if names[ic.Name] {
			err = errors.Join(err, fmt.Errorf("%s: duplicate name %q", prefix, ic.Name))
		}
		names[ic.Name] = true

		if ic.Issuer == "" {
			err = errors.Join(err, fmt.Errorf("%s: issuer is required", prefix))
		}
		if ic.Audience == "" {
			err = errors.Join(err, fmt.Errorf("%s: audience is required", prefix))
		}

		if ic.Login != nil {
			logins++
			if ic.Login.ClientID == "" {
				err = errors.Join(err, fmt.Errorf("%s: login.client_id is required", prefix))
			}
		}

		for claim, patterns := range ic.Claims {
			if claim == "" {
				err = errors.Join(err, fmt.Errorf("%s: claims: claim name must not be empty", prefix))
			}
			if len(patterns) == 0 {
				err = errors.Join(err, fmt.Errorf("%s: claims.%s: at least one pattern is required", prefix, claim))
			}
			for _, p := range patterns {
				if p == "" {
					err = errors.Join(err, fmt.Errorf("%s: claims.%s: patterns must not be empty", prefix, claim))
				}
			}
		}
	}

	if logins > 1 {
		err = errors.Join(err, fmt.Errorf("oidc: only one issuer may have login, %d do", logins))
	}
	return err
}
