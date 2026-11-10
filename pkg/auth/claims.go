package auth

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// ClaimRules maps a top-level JWT claim name to the patterns its value may match.
// All claims must match, and a claim matches if any of its patterns matches.
// In a pattern, "*" matches any run of characters (including "/"), everything else is literal and case-sensitive.
// A claim matches when it is a string, or an array containing a string, that matches a pattern.
// Missing claims and claims of any other type never match.
type ClaimRules map[string][]string

// Match returns an error naming the first claim that doesn't satisfy the rules.
// The error never contains claim values from the token.
func (r ClaimRules) Match(claims map[string]any) error {
	names := make([]string, 0, len(r))
	for name := range r {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		value, ok := claims[name]
		if !ok {
			return fmt.Errorf("claim %q is missing", name)
		}
		if !matchClaim(r[name], value) {
			return fmt.Errorf("claim %q does not match any allowed pattern", name)
		}
	}
	return nil
}

func matchClaim(patterns []string, value any) bool {
	switch v := value.(type) {
	case string:
		return slices.ContainsFunc(patterns, func(p string) bool { return matchPattern(p, v) })
	case []any:
		for _, element := range v {
			if s, ok := element.(string); ok && matchClaim(patterns, s) {
				return true
			}
		}
	}
	return false
}

// matchPattern reports whether value matches the whole pattern, where "*" matches any run of characters.
// path.Match isn't used because its "*" doesn't match "/" and it treats "?" and "[" specially.
func matchPattern(pattern, value string) bool {
	segments := strings.Split(pattern, "*")
	if len(segments) == 1 {
		return pattern == value
	}

	first, last := segments[0], segments[len(segments)-1]
	if len(value) < len(first)+len(last) || !strings.HasPrefix(value, first) || !strings.HasSuffix(value, last) {
		return false
	}

	// Find the middle segments left to right in what remains between the prefix and the suffix
	rest := value[len(first) : len(value)-len(last)]
	for _, segment := range segments[1 : len(segments)-1] {
		i := strings.Index(rest, segment)
		if i < 0 {
			return false
		}
		rest = rest[i+len(segment):]
	}
	return true
}
