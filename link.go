package ofauth

// OFAuth Link: the OAuth 2.0 Authorization Code flow with PKCE.
//
// Run this on your backend. It holds the client secret and PKCE verifier,
// which must never reach a browser or native app.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Environment is sandbox, test, or live. Each environment has its own OAuth client.
type Environment string

// Environments.
const (
	EnvironmentSandbox Environment = "sandbox"
	EnvironmentTest    Environment = "test"
	EnvironmentLive    Environment = "live"
)

var clientIDPattern = regexp.MustCompile(`^ofext_(sandbox|test|live)_`)

// EnvironmentFromClientID returns the environment a client ID belongs to
// (ofext_live_... -> live), or "" when the ID has no known prefix.
func EnvironmentFromClientID(clientID string) Environment {
	m := clientIDPattern.FindStringSubmatch(clientID)
	if m == nil {
		return ""
	}
	return Environment(m[1])
}

// LinkConfig configures a Link.
type LinkConfig struct {
	// ClientID for one environment, e.g. ofext_live_....
	ClientID string
	// ClientSecret is required for ExchangeCode, Refresh, and Revoke.
	ClientSecret string
	// ClientAuthentication is client_secret_basic (default) or client_secret_post.
	ClientAuthentication string
	// RedirectURI is the default redirect URI. It must exactly match a URI
	// registered for the client.
	RedirectURI string
	// AuthURL is the origin of the browser authorize route. Defaults to DefaultAuthURL.
	AuthURL string
	// APIURL is the origin of the token and revoke endpoints. Defaults to DefaultAPIURL.
	APIURL string
	// HTTPClient defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// Link is the OAuth client for one environment.
//
//	link := ofauth.NewLink(ofauth.LinkConfig{ClientID: id, ClientSecret: secret, RedirectURI: redirect})
//	authz, _ := link.CreateAuthorizationURL(ofauth.AuthorizationURLOptions{
//		Scopes: []ofauth.Scope{ofauth.ScopeProfileRead},
//	})
//	// store authz.State and authz.CodeVerifier, redirect to authz.URL; then on the callback:
//	cb, err := link.ParseCallback(r.URL.String(), storedState)
//	tokens, err := link.ExchangeCode(ctx, ofauth.ExchangeCodeOptions{Code: cb.Code, CodeVerifier: storedVerifier})
type Link struct {
	clientID             string
	clientSecret         string
	clientAuthentication string
	redirectURI          string
	authURL              string
	apiURL               string
	httpClient           *http.Client
}

// NewLink returns a Link for one OAuth client.
func NewLink(config LinkConfig) *Link {
	l := &Link{
		clientID:             config.ClientID,
		clientSecret:         config.ClientSecret,
		clientAuthentication: config.ClientAuthentication,
		redirectURI:          config.RedirectURI,
		authURL:              strings.TrimRight(config.AuthURL, "/"),
		apiURL:               strings.TrimRight(config.APIURL, "/"),
		httpClient:           config.HTTPClient,
	}
	if l.authURL == "" {
		l.authURL = DefaultAuthURL
	}
	if l.apiURL == "" {
		l.apiURL = DefaultAPIURL
	}
	if l.httpClient == nil {
		l.httpClient = http.DefaultClient
	}
	return l
}

// ClientID returns the client ID.
func (l *Link) ClientID() string { return l.clientID }

// Environment is derived from the client ID.
func (l *Link) Environment() Environment { return EnvironmentFromClientID(l.clientID) }

// AuthorizationURLOptions configures CreateAuthorizationURL.
type AuthorizationURLOptions struct {
	// Scopes to request. Add ScopeOfflineAccess to receive a refresh token.
	Scopes []Scope
	// Operations adds the scopes these operations need (canonical dotted
	// names, see ScopesFor), merged with Scopes.
	Operations []string
	// RedirectURI defaults to LinkConfig.RedirectURI.
	RedirectURI string
	// State is a one-use value. Generated when empty.
	State string
	// CodeVerifier is the PKCE verifier. Generated when empty.
	CodeVerifier string
}

// AuthorizationRequest is the result of CreateAuthorizationURL.
type AuthorizationRequest struct {
	// URL to send the user's browser to.
	URL string
	// State: store with the pending authorization and check it on the callback.
	State string
	// CodeVerifier: store on your backend; needed to exchange the code.
	CodeVerifier string
	// CodeChallenge is the S256 challenge sent in URL.
	CodeChallenge string
}

// AuthorizationCallback is a successful authorization callback.
type AuthorizationCallback struct {
	// Code is the authorization code to exchange.
	Code string
	// State is the state from the authorization request.
	State string
}

// AuthorizationError is returned by ParseCallback when the user denied
// access, the request was invalid, or the state does not match.
type AuthorizationError struct {
	// Code is access_denied, invalid_request, or invalid_state.
	Code string
	// State is the callback's state, when present.
	State string
	// Description is error_description or a local explanation.
	Description string
}

// Error implements error.
func (e *AuthorizationError) Error() string {
	if e.Description != "" {
		return "ofauth: authorization failed: " + e.Code + ": " + e.Description
	}
	return "ofauth: authorization failed: " + e.Code
}

// OAuthError is an RFC 6749 error from the token or revoke endpoint.
// Code invalid_grant on Refresh means the user must authorize again
// (NeedsReauthorization).
type OAuthError struct {
	// StatusCode is the HTTP status.
	StatusCode int
	// Code is the RFC 6749 error code, e.g. invalid_grant or invalid_client.
	Code string
	// Description is error_description, when sent.
	Description string
	// Reason is client_deleted, developer_plan_unavailable, or security_suspended, when set.
	Reason string
	// RecoveryAction says what to do next, when sent.
	RecoveryAction RecoveryAction
	// RetryAfter is the Retry-After delay. Zero when absent.
	RetryAfter time.Duration
	// Body is the raw response body.
	Body []byte
}

// NeedsReauthorization reports that the user must authorize again: code
// invalid_grant (the refresh token is no longer valid) or a recovery action
// that restarts authorization.
func (e *OAuthError) NeedsReauthorization() bool {
	return e.Code == "invalid_grant" || e.RecoveryAction.needsReauthorization()
}

// Error implements error.
func (e *OAuthError) Error() string {
	msg := fmt.Sprintf("ofauth: oauth %d %s", e.StatusCode, e.Code)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

func newOAuthError(resp *http.Response, data []byte) *OAuthError {
	e := &OAuthError{StatusCode: resp.StatusCode, Body: data, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	var body struct {
		Error       any `json:"error"`
		Description any `json:"error_description"`
		Reason      any `json:"reason"`
		Recovery    any `json:"recovery"`
	}
	if json.Unmarshal(data, &body) == nil {
		e.Code, _ = body.Error.(string)
		e.Description, _ = body.Description.(string)
		e.Reason, _ = body.Reason.(string)
		if recovery, ok := body.Recovery.(map[string]any); ok {
			action, _ := recovery["action"].(string)
			e.RecoveryAction = RecoveryAction(action)
		}
	}
	if e.Code == "" {
		e.Code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return e
}

func base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64URL(buf), nil
}

// CodeChallenge returns the S256 PKCE challenge for a verifier.
func CodeChallenge(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64URL(sum[:])
}

// GeneratePKCE returns a new verifier (43 characters) and its S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	verifier, err = randomToken()
	if err != nil {
		return "", "", err
	}
	return verifier, CodeChallenge(verifier), nil
}

// CreateAuthorizationURL builds the URL to send the user to, with a fresh
// state and PKCE pair unless provided.
func (l *Link) CreateAuthorizationURL(opts AuthorizationURLOptions) (*AuthorizationRequest, error) {
	redirectURI := opts.RedirectURI
	if redirectURI == "" {
		redirectURI = l.redirectURI
	}
	if redirectURI == "" {
		return nil, errors.New("ofauth: CreateAuthorizationURL needs a RedirectURI")
	}
	state := opts.State
	if state == "" {
		var err error
		if state, err = randomToken(); err != nil {
			return nil, err
		}
	}
	verifier := opts.CodeVerifier
	if verifier == "" {
		var err error
		if verifier, err = randomToken(); err != nil {
			return nil, err
		}
	}
	challenge := CodeChallenge(verifier)
	requested, err := mergeScopes(opts.Scopes, opts.Operations)
	if err != nil {
		return nil, err
	}
	scopes := make([]string, len(requested))
	for i, s := range requested {
		scopes[i] = string(s)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", l.clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return &AuthorizationRequest{
		URL:           l.authURL + "/v3/authorize?" + q.Encode(),
		State:         state,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}, nil
}

// ParseCallback reads the callback URL (or its query string). It returns
// *AuthorizationError for error=... callbacks, a missing code, and, when
// expectedState is non-empty, a state mismatch (invalid_state).
func (l *Link) ParseCallback(callback string, expectedState string) (*AuthorizationCallback, error) {
	raw := callback
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, &AuthorizationError{Code: "invalid_request", Description: "malformed callback query"}
	}
	return l.ParseCallbackQuery(query, expectedState)
}

// ParseCallbackQuery is ParseCallback for already parsed query values
// (e.g. r.URL.Query()).
func (l *Link) ParseCallbackQuery(query url.Values, expectedState string) (*AuthorizationCallback, error) {
	for _, name := range []string{"code", "state", "iss", "error"} {
		if len(query[name]) > 1 {
			return nil, &AuthorizationError{Code: "invalid_request"}
		}
	}
	state := query.Get("state")
	if expectedState == "" || state != expectedState {
		return nil, &AuthorizationError{Code: "invalid_state", State: state, Description: "state does not match the pending authorization"}
	}
	if query.Get("iss") != l.apiURL+"/v3/link" {
		return nil, &AuthorizationError{Code: "invalid_issuer"}
	}
	if code := query.Get("error"); code != "" {
		return nil, &AuthorizationError{Code: code, State: state, Description: query.Get("error_description")}
	}
	code := query.Get("code")
	if code == "" || state == "" {
		return nil, &AuthorizationError{Code: "invalid_request", State: state, Description: "missing code or state"}
	}
	return &AuthorizationCallback{Code: code, State: state}, nil
}

// ExchangeCodeOptions configures ExchangeCode.
type ExchangeCodeOptions struct {
	// Code from the callback.
	Code string
	// CodeVerifier from the authorization request.
	CodeVerifier string
	// RedirectURI used in the authorization request. Defaults to LinkConfig.RedirectURI.
	RedirectURI string
}

// ExchangeCode exchanges an authorization code for tokens.
func (l *Link) ExchangeCode(ctx context.Context, opts ExchangeCodeOptions) (*LinkTokenResponse, error) {
	redirectURI := opts.RedirectURI
	if redirectURI == "" {
		redirectURI = l.redirectURI
	}
	if redirectURI == "" {
		return nil, errors.New("ofauth: ExchangeCode needs the RedirectURI used in the authorization request")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", opts.Code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", opts.CodeVerifier)
	return l.tokenRequest(ctx, form)
}

// RefreshOptions configures Refresh.
type RefreshOptions struct {
	// RefreshToken is the stable client-bound refresh token.
	RefreshToken string
	// Scope optionally narrows the scopes of the new access token.
	Scope []Scope
}

// Refresh issues a new access token and echoes the stable client-bound refresh token.
func (l *Link) Refresh(ctx context.Context, opts RefreshOptions) (*LinkTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", opts.RefreshToken)
	setScope(form, opts.Scope)
	return l.tokenRequest(ctx, form)
}

func setScope(form url.Values, scope []Scope) {
	if len(scope) == 0 {
		return
	}
	scopes := make([]string, len(scope))
	for i, s := range scope {
		scopes[i] = string(s)
	}
	form.Set("scope", strings.Join(scopes, " "))
}

// RevokeOptions configures Revoke.
type RevokeOptions struct {
	// Token is the refresh token (or access token) to revoke.
	Token string
	// TokenTypeHint is "refresh_token" or "access_token" (optional).
	TokenTypeHint string
}

// Revoke ends one access token, or a refresh credential and all its access tokens.
func (l *Link) Revoke(ctx context.Context, opts RevokeOptions) error {
	form := url.Values{}
	form.Set("token", opts.Token)
	if opts.TokenTypeHint != "" {
		form.Set("token_type_hint", opts.TokenTypeHint)
	}
	_, err := l.formRequest(ctx, "/v3/link/revoke", form)
	return err
}

// Metadata fetches the RFC 8414 authorization server metadata.
func (l *Link) Metadata(ctx context.Context) (*LinkAuthorizationServerMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.apiURL+"/.well-known/oauth-authorization-server/v3/link", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, data, err := l.send(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newOAuthError(resp, data)
	}
	var out LinkAuthorizationServerMetadata
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("ofauth: decode metadata: %w", err)
	}
	return &out, nil
}

func (l *Link) tokenRequest(ctx context.Context, form url.Values) (*LinkTokenResponse, error) {
	data, err := l.formRequest(ctx, "/v3/link/token", form)
	if err != nil {
		return nil, err
	}
	var out LinkTokenResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("ofauth: decode token response: %w", err)
	}
	return &out, nil
}

func (l *Link) formRequest(ctx context.Context, path string, form url.Values) ([]byte, error) {
	if l.clientSecret == "" {
		return nil, fmt.Errorf("ofauth: %s needs the client secret", path)
	}
	if l.clientAuthentication == "client_secret_post" {
		form.Set("client_id", l.clientID)
		form.Set("client_secret", l.clientSecret)
	} else if l.clientAuthentication != "" && l.clientAuthentication != "client_secret_basic" {
		return nil, errors.New("ofauth: unsupported client authentication")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.apiURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	credentials := url.QueryEscape(l.clientID) + ":" + url.QueryEscape(l.clientSecret)
	if l.clientAuthentication != "client_secret_post" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, data, err := l.send(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newOAuthError(resp, data)
	}
	return data, nil
}

func (l *Link) send(req *http.Request) (*http.Response, []byte, error) {
	client := *l.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, data, nil
}
