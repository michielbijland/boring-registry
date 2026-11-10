package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"frasers-org", "frasers-org", true},
		{"frasers-org", "frasers-org-evil", false},
		{"frasers-org", "Frasers-Org", false},
		{"frasers-org/*", "frasers-org/infra", true},
		{"frasers-org/*", "frasers-org/a/b", true},
		{"frasers-org/*", "frasers-org", false},
		{"frasers-org/*", "frasers-org/", true},
		{"refs/tags/v*", "refs/tags/v1.2.3", true},
		{"*", "", true},
		{"*", "anything/at/all", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"*-prod", "frasers-prod", true},
		{"*-prod", "frasers-prod-2", false},
		{"a*a", "a", false}, // prefix and suffix must not overlap
		{"a*a", "aa", true},
		{"a?c", "abc", false}, // only * is special
		{"a[b]c", "a[b]c", true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, matchPattern(tt.pattern, tt.value), "pattern=%q value=%q", tt.pattern, tt.value)
	}
}

func TestClaimRulesMatch(t *testing.T) {
	tests := []struct {
		name    string
		rules   ClaimRules
		claims  map[string]any
		wantErr string // "" means match
	}{
		{"no rules", nil, map[string]any{"sub": "x"}, ""},
		{"string match", ClaimRules{"repository_owner": {"frasers-org"}}, map[string]any{"repository_owner": "frasers-org"}, ""},
		{"string mismatch", ClaimRules{"repository_owner": {"frasers-org"}}, map[string]any{"repository_owner": "other"}, "repository_owner"},
		{"OR within claim", ClaimRules{"ref": {"refs/heads/main", "refs/tags/v*"}}, map[string]any{"ref": "refs/tags/v1"}, ""},
		{"AND across claims", ClaimRules{"repository_owner": {"frasers-org"}, "ref": {"refs/heads/main"}}, map[string]any{"repository_owner": "frasers-org", "ref": "refs/heads/dev"}, "ref"},
		{"missing claim", ClaimRules{"groups": {"g1"}}, map[string]any{"sub": "x"}, "groups"},
		{"array any element", ClaimRules{"groups": {"g2"}}, map[string]any{"groups": []any{"g1", "g2"}}, ""},
		{"array no element", ClaimRules{"groups": {"g3"}}, map[string]any{"groups": []any{"g1", "g2"}}, "groups"},
		{"array non-string elements ignored", ClaimRules{"groups": {"1"}}, map[string]any{"groups": []any{float64(1), true}}, "groups"},
		{"number claim fails", ClaimRules{"run_attempt": {"1"}}, map[string]any{"run_attempt": float64(1)}, "run_attempt"},
		{"bool claim fails", ClaimRules{"ref_protected": {"true"}}, map[string]any{"ref_protected": true}, "ref_protected"},
		{"null claim fails", ClaimRules{"sub": {"*"}}, map[string]any{"sub": nil}, "sub"},
		{"object claim fails", ClaimRules{"o": {"*"}}, map[string]any{"o": map[string]any{"a": "b"}}, "o"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rules.Match(tt.claims)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestClaimRulesMatchErrorOmitsValues(t *testing.T) {
	err := ClaimRules{"repository_owner": {"frasers-org"}}.Match(map[string]any{"repository_owner": "secret-value"})
	if assert.Error(t, err) {
		assert.NotContains(t, err.Error(), "secret-value")
	}
}
