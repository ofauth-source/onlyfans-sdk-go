package ofauth

// Scope helpers built on the generated operation -> scope map (operations.go).

import (
	"errors"
	"fmt"
	"slices"
)

// RequiredScope returns the OAuth scope an operation needs, by canonical
// dotted name (e.g. "access.chats.messages.send"; see the "Operation" line of
// each method's doc comment). known is false for unknown names; scope is ""
// for operations that need no scope (linked accounts).
func RequiredScope(operation string) (scope Scope, known bool) {
	scope, known = operationScopes[operation]
	return scope, known
}

// ScopesFor returns the sorted, de-duplicated scopes needed by the given
// operations (canonical dotted names). An unknown name is an error.
//
//	scopes, err := ofauth.ScopesFor("access.chats.messages.send", "access.profile.get")
//	// [messages:write profile:read]
func ScopesFor(operations ...string) ([]Scope, error) {
	scopes := []Scope{}
	for _, op := range operations {
		scope, known := operationScopes[op]
		if !known {
			return nil, fmt.Errorf("ofauth: unknown operation %q", op)
		}
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	slices.Sort(scopes)
	return slices.Compact(scopes), nil
}

// MissingScopes returns the scope to request again when err is an *APIError
// with code missing_scope or additional_consent_required (its
// RequiredScope), and nil otherwise.
func MissingScopes(err error) []Scope {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RequiredScope == "" {
		return nil
	}
	if apiErr.Code != "missing_scope" && apiErr.Code != "additional_consent_required" {
		return nil
	}
	return []Scope{apiErr.RequiredScope}
}

// NeedsReauthorization reports whether err (anywhere in its chain) means the
// user must authorize again: an *APIError or *OAuthError whose
// NeedsReauthorization is true (e.g. invalid_grant on refresh), or a
// protocol error.
func NeedsReauthorization(err error) bool {
	var target interface{ NeedsReauthorization() bool }
	return errors.As(err, &target) && target.NeedsReauthorization()
}

// mergeScopes appends the scopes of operations to scopes, keeping order and
// dropping duplicates.
func mergeScopes(scopes []Scope, operations []string) ([]Scope, error) {
	out := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(operations) == 0 {
		return out, nil
	}
	extra, err := ScopesFor(operations...)
	if err != nil {
		return nil, err
	}
	for _, s := range extra {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}
