package enum

import (
	"sort"
	"strings"
)

// ScopeSet provides normalized handling of OAuth2 scope strings (space-delimited per RFC 6749).
type ScopeSet struct{ items map[string]struct{} }

func ParseScopeString(s string) ScopeSet {
	ss := ScopeSet{items: map[string]struct{}{}}
	for _, part := range strings.Fields(s) {
		if part == "" {
			continue
		}
		ss.items[part] = struct{}{}
	}
	return ss
}

func (s ScopeSet) Has(scope string) bool {
	_, ok := s.items[scope]
	return ok
}

// Merge returns a new ScopeSet containing union of scopes.
func (s ScopeSet) Merge(other ScopeSet) ScopeSet {
	out := ScopeSet{items: map[string]struct{}{}}
	for k := range s.items {
		out.items[k] = struct{}{}
	}
	for k := range other.items {
		out.items[k] = struct{}{}
	}
	return out
}

// String returns a deterministic, alphabetical representation for stable comparisons & caching keys.
func (s ScopeSet) String() string {
	if len(s.items) == 0 {
		return ""
	}
	arr := make([]string, 0, len(s.items))
	for k := range s.items {
		arr = append(arr, k)
	}
	sort.Strings(arr)
	return strings.Join(arr, " ")
}
