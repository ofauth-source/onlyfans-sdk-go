package ofauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// DefaultAPIURL is the API origin.
	DefaultAPIURL = "https://api.ofauth.com"
	// DefaultAuthURL is the origin of the browser authorize route.
	DefaultAuthURL = "https://link.ofauth.com"
	// LinkedAccountHeader carries the linked account for Access and Vault+ operations.
	LinkedAccountHeader = "x-linked-account-id"
)

// Retry and timeout defaults. See Config.MaxRetries, Config.Timeout, and
// Config.MaxRetryDelay.
const (
	// DefaultMaxRetries is how many times a failed request is retried.
	DefaultMaxRetries = 2
	// DefaultTimeout limits each attempt of a request.
	DefaultTimeout = 60 * time.Second
	// DefaultMaxRetryDelay is the longest server-requested delay the client waits before retrying.
	DefaultMaxRetryDelay = 60 * time.Second
	// UploadPartTimeout is the minimum per-attempt timeout for the part PUTs of UploadMedia.
	UploadPartTimeout = 300 * time.Second
)

const (
	retryBaseDelay = 500 * time.Millisecond
	retryMaxDelay  = 8 * time.Second
)

// ============================================================================
// Access tokens
// ============================================================================

// TokenSource hands out bearer access tokens.
//
// forceRefresh is true when the API rejected the previous token
// (invalid_token): implementations should refresh instead of returning a
// cached token. The caller owns token renewal.
type TokenSource interface {
	AccessToken(ctx context.Context, forceRefresh bool) (string, error)
}

// StaticToken is a fixed access token. You refresh it yourself; requests
// rejected with invalid_token are not retried.
type StaticToken string

// AccessToken returns the token.
func (t StaticToken) AccessToken(context.Context, bool) (string, error) {
	return string(t), nil
}

// TokenFunc adapts a function to TokenSource. Requests rejected with
// invalid_token are retried once with forceRefresh set.
type TokenFunc func(ctx context.Context, forceRefresh bool) (string, error)

// AccessToken calls f.
func (f TokenFunc) AccessToken(ctx context.Context, forceRefresh bool) (string, error) {
	return f(ctx, forceRefresh)
}

// ============================================================================
// Config and requests
// ============================================================================

// Config configures a Client.
type Config struct {
	// AccessToken is the bearer token source for one authorization: a
	// StaticToken, a TokenFunc, a caller-owned TokenSource.
	// Required.
	AccessToken TokenSource
	// LinkedAccountID is the default linked account for Access and Vault+
	// operations (sent as x-linked-account-id). Each call can override it
	// with its LinkedAccountID param.
	LinkedAccountID string
	// BaseURL is the API origin. Defaults to DefaultAPIURL.
	BaseURL string
	// HTTPClient sends requests. Defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Header holds extra headers sent with every request. Names are
	// case-insensitive; Accept, Content-Type, and x-linked-account-id set by
	// the SDK win. Authorization is not allowed (requests fail with
	// ErrAuthorizationHeader): the SDK sends the bearer token from AccessToken.
	Header http.Header

	// MaxRetries is how many times a failed request is retried: network
	// errors and per-attempt timeouts (GET, PUT, DELETE only; see
	// ConnectionError), 429, 503
	// authorization_temporarily_unavailable, and 502/503/504 (GET, PUT,
	// DELETE only). nil uses DefaultMaxRetries; ofauth.Ptr(0) disables retries.
	MaxRetries *int
	// Timeout limits each attempt, including reading the response body. 0
	// uses DefaultTimeout; a negative value disables the per-attempt timeout.
	// Upload part PUTs use at least UploadPartTimeout.
	Timeout time.Duration
	// MaxRetryDelay caps server-requested delays (Retry-After,
	// RateLimit-Reset): when the server asks to wait longer, the error is
	// returned instead of retrying. 0 uses DefaultMaxRetryDelay.
	MaxRetryDelay time.Duration

	// OnRequest is called before each attempt, with a sanitized URL and
	// redacted headers (see RequestInfo). Panics in the hook are recovered and
	// ignored.
	OnRequest func(info RequestInfo)
	// OnResponse is called after each attempt, including failed ones (Err set).
	// Panics in the hook are recovered and ignored.
	OnResponse func(info ResponseInfo)
	// Debug logs one line per attempt and each retry to the standard logger,
	// e.g. "[ofauth] GET /v3/access/profile -> 200 (123ms, req_abc)". Tokens,
	// secrets, and bodies are never logged. Also enabled by OFAUTH_DEBUG=1.
	Debug bool
	// DebugLogger receives the debug lines instead of the standard logger.
	// Setting it enables debug logging.
	DebugLogger func(line string)
}

// RequestInfo describes one attempt about to be sent. See Config.OnRequest.
type RequestInfo struct {
	Method string
	// URL is the request URL without credentials: the values of
	// credential-like query parameters (signatures, tokens, keys, X-Amz-*)
	// read REDACTED.
	URL string
	// Header is a copy of the request headers with credential values
	// redacted, whatever their casing: Authorization ("Bearer [REDACTED]"),
	// Cookie, X-Api-Key, Cf-Access-Client-Secret, and any name containing
	// "token", "secret", or "password" ("[REDACTED]").
	Header http.Header
	// Attempt is 1 for the first attempt.
	Attempt int
}

// ResponseInfo describes the outcome of one attempt. See Config.OnResponse.
type ResponseInfo struct {
	Method string
	// URL is sanitized as in RequestInfo.
	URL string
	// StatusCode is 0 when the attempt failed without a response (Err is set).
	StatusCode int
	// RequestID is the x-request-id header (or the error body's requestId).
	RequestID string
	Duration  time.Duration
	// Attempt is 1 for the first attempt.
	Attempt int
	// Err is the transport error (network error, timeout, or an error
	// returned by a custom http.RoundTripper), when there was no response.
	Err error
}

// Request is one low-level API call. Generated methods build it for you; use
// Client.Do directly only for operations the SDK does not cover yet.
type Request struct {
	// Method is the HTTP method.
	Method string
	// Path below the API origin, e.g. "/v3/access/profile".
	Path string
	// Query holds the query parameters.
	Query url.Values
	// Body is encoded as JSON when non-nil.
	Body any
	// RawBody is sent as-is with ContentType (uploads). Takes precedence over Body.
	RawBody []byte
	// ContentType of RawBody. Defaults to application/octet-stream.
	ContentType string
	// LinkedAccount marks operations that require x-linked-account-id.
	LinkedAccount bool
	// LinkedAccountID overrides Config.LinkedAccountID for this call.
	LinkedAccountID string
	// URL is an absolute URL to call instead of BaseURL + Path. It must be on
	// the BaseURL origin (scheme, host, and port); any other origin fails with
	// ErrCrossOriginURL before anything is sent.
	URL string
	// Header holds extra headers for this call. Same rules as Config.Header.
	Header http.Header
	// Operation is the canonical operation name (e.g. "access.profile.get"),
	// copied to APIError.Operation and used to fill APIError.RequiredScope.
	Operation string
	// MaxRetries overrides Config.MaxRetries for this call.
	MaxRetries *int
	// Timeout overrides Config.Timeout for this call.
	Timeout time.Duration
}

// ErrLinkedAccountRequired is returned (wrapped) when an operation needs a
// linked account and neither the call nor the client config sets one.
var ErrLinkedAccountRequired = errors.New("ofauth: operation needs a linked account: set LinkedAccountID on the params or the client config")

// ErrNoAccessToken is returned when Config.AccessToken is nil.
var ErrNoAccessToken = errors.New("ofauth: Config.AccessToken is required")

// ErrCrossOriginURL is returned (wrapped) when Request.URL is not an absolute
// URL on the BaseURL origin. Requests carry the access token and the linked
// account header, so they are refused before anything is sent.
var ErrCrossOriginURL = errors.New("ofauth: refusing to send the access token to a URL outside the API origin")

// ErrAuthorizationHeader is returned (wrapped) when Config.Header or
// Request.Header sets Authorization, in any casing. The SDK owns that header
// and always sends "Bearer <access token>" from Config.AccessToken; a second
// credential would otherwise be sent next to it or silently replaced.
var ErrAuthorizationHeader = errors.New("ofauth: do not set the Authorization header: the SDK sends the bearer token from Config.AccessToken")

// checkCallerHeaders returns ErrAuthorizationHeader when any of headers sets
// Authorization, whatever its casing.
func checkCallerHeaders(headers ...http.Header) error {
	for _, header := range headers {
		for name := range header {
			if strings.EqualFold(name, "Authorization") {
				return fmt.Errorf("%w (found %q in the headers)", ErrAuthorizationHeader, name)
			}
		}
	}
	return nil
}

// sensitiveHeaders are header names (lowercase) whose values are credentials.
var sensitiveHeaders = map[string]bool{
	"authorization":           true,
	"proxy-authorization":     true,
	"cookie":                  true,
	"set-cookie":              true,
	"x-api-key":               true,
	"api-key":                 true,
	"cf-access-client-secret": true,
}

func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	return sensitiveHeaders[lower] || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password")
}

// isSensitiveQueryKey reports query parameter names whose values may be
// credentials, e.g. X-Amz-Signature, token, sig, or api_key.
func isSensitiveQueryKey(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "x-amz-") || strings.HasPrefix(lower, "x-goog-") {
		return true
	}
	for _, part := range []string{"token", "secret", "sig", "key", "password", "credential", "auth", "session"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// sanitizeURL returns raw for hooks, logs, and errors: no user info or
// fragment, and the values of credential-like query parameters (signatures,
// tokens, keys, X-Amz-*) replaced by REDACTED. Other parameters (limit,
// cursor, linkedAccountId, ...) are kept so hooks stay useful for debugging.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	if u.RawQuery != "" {
		pairs := strings.Split(u.RawQuery, "&")
		kept := pairs[:0]
		for _, pair := range pairs {
			if pair == "" {
				continue
			}
			name, _, _ := strings.Cut(pair, "=")
			decoded, err := url.QueryUnescape(name)
			if err != nil {
				decoded = name
			}
			if isSensitiveQueryKey(decoded) {
				pair = name + "=REDACTED"
			}
			kept = append(kept, pair)
		}
		u.RawQuery = strings.Join(kept, "&")
	}
	return u.String()
}

// sanitizeErrorURL replaces the URL inside a *url.Error in err's chain (the
// net/http client puts the full request URL there, and its Error() prints it)
// with sanitizeURL's form. err is the SDK's own transport error, so it is
// changed in place.
func sanitizeErrorURL(err error) {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = sanitizeURL(urlErr.URL)
	}
}

// realtimeURLFor returns the Realtime event stream URL on the API origin of
// baseURL: "https://host" becomes "https://host/v3/realtime/events".
// Realtime is served on the same origin as every other API route, so
// Client.Realtime always streams from here.
func realtimeURLFor(baseURL string) (string, error) {
	base := strings.TrimRight(baseURL, "/")
	scheme, rest, ok := strings.Cut(base, "://")
	if ok && rest != "" && (strings.EqualFold(scheme, "https") || strings.EqualFold(scheme, "http")) {
		return base + realtimeEventsPath, nil
	}
	return "", fmt.Errorf("ofauth: cannot derive the Realtime URL from BaseURL %q: it is not an http(s) URL", base)
}

// originOf returns scheme://host:port for an absolute http(s) URL, with the
// default port filled in, or "" when raw is not one.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch {
	case scheme != "http" && scheme != "https", u.Hostname() == "":
		return ""
	case port == "" && scheme == "https":
		port = "443"
	case port == "" && scheme == "http":
		port = "80"
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// checkSameOrigin returns nil when target is on the API origin.
func checkSameOrigin(target, base string) error {
	origin := originOf(target)
	if origin == "" {
		return fmt.Errorf("%w: request URL is not an absolute http(s) URL", ErrCrossOriginURL)
	}
	if apiOrigin := originOf(base); origin != apiOrigin {
		return fmt.Errorf("%w: %s is not the API origin (%s)", ErrCrossOriginURL, origin, apiOrigin)
	}
	return nil
}

func missingParam(name string) error {
	return fmt.Errorf("ofauth: %s is required", name)
}

// clientRuntime holds a client's clock, sleep, jitter, and debug logger.
// Tests replace sleep and jitter so retries never wait for real.
type clientRuntime struct {
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func() float64
	logf   func(line string)
}

func newClientRuntime(config Config) *clientRuntime {
	return &clientRuntime{sleep: sleepContext, jitter: rand.Float64, logf: debugLogger(config.Debug, config.DebugLogger)}
}

// debugLogger resolves the Debug and DebugLogger options (and OFAUTH_DEBUG=1)
// to a line logger, or nil when debug logging is off.
func debugLogger(debug bool, logger func(line string)) func(line string) {
	switch {
	case logger != nil:
		return logger
	case debug || os.Getenv("OFAUTH_DEBUG") == "1":
		return func(line string) { log.Print(line) }
	}
	return nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) runtime() *clientRuntime {
	return c.rt
}

func (c *Client) debugf(format string, args ...any) {
	if logf := c.runtime().logf; logf != nil {
		callHook(func() { logf("[ofauth] " + fmt.Sprintf(format, args...)) })
	}
}

func (c *Client) httpClient() *http.Client {
	if c.config.HTTPClient != nil {
		return c.config.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) baseURL() string {
	if c.config.BaseURL != "" {
		return strings.TrimRight(c.config.BaseURL, "/")
	}
	return DefaultAPIURL
}

func (c *Client) timeout() time.Duration {
	if c.config.Timeout == 0 {
		return DefaultTimeout
	}
	return c.config.Timeout
}

func (c *Client) maxRetryDelay() time.Duration {
	if c.config.MaxRetryDelay <= 0 {
		return DefaultMaxRetryDelay
	}
	return c.config.MaxRetryDelay
}

// WithLinkedAccount returns a client for another linked account of the same
// authorization. It shares the token source and HTTP client.
func (c *Client) WithLinkedAccount(linkedAccountID string) *Client {
	config := c.config
	config.LinkedAccountID = linkedAccountID
	next := NewClient(config)
	next.rt = c.runtime()
	return next
}

// LinkedAccountID returns the client's default linked account.
func (c *Client) LinkedAccountID() string {
	return c.config.LinkedAccountID
}

// Do sends one request and decodes a JSON response into out (when out is
// non-nil and the response has a body). Non-2xx responses return *APIError;
// network failures, per-attempt timeouts, and the caller's cancellation return
// *ConnectionError. Any other error from the HTTP client's transport (e.g. a
// custom http.RoundTripper refusing a request) is returned as-is, without
// retrying. Failed attempts are retried as described on Config.MaxRetries.
func (c *Client) Do(ctx context.Context, req *Request, out any) error {
	if c.config.AccessToken == nil {
		return ErrNoAccessToken
	}
	linkedAccountID := req.LinkedAccountID
	if linkedAccountID == "" {
		linkedAccountID = c.config.LinkedAccountID
	}
	if req.LinkedAccount && linkedAccountID == "" {
		return fmt.Errorf("%s %s: %w", req.Method, req.Path, ErrLinkedAccountRequired)
	}

	target := req.URL
	if target == "" {
		target = c.baseURL() + req.Path
		if len(req.Query) > 0 {
			target += "?" + req.Query.Encode()
		}
	} else if err := checkSameOrigin(target, c.baseURL()); err != nil {
		return err
	}
	if err := checkCallerHeaders(c.config.Header, req.Header); err != nil {
		return err
	}
	// Hooks and errors only ever see this form of the URL.
	safeURL := sanitizeURL(target)
	logPath := req.Path
	if u, err := url.Parse(target); err == nil {
		logPath = u.Path
	}

	var payload []byte
	contentType := ""
	switch {
	case req.RawBody != nil:
		payload = req.RawBody
		contentType = req.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
	case req.Body != nil:
		encoded, err := json.Marshal(req.Body)
		if err != nil {
			return fmt.Errorf("ofauth: encode request body: %w", err)
		}
		payload = encoded
		contentType = "application/json"
	}

	maxRetries := DefaultMaxRetries
	if req.MaxRetries != nil {
		maxRetries = *req.MaxRetries
	} else if c.config.MaxRetries != nil {
		maxRetries = *c.config.MaxRetries
	}
	timeout := c.timeout()
	if req.Timeout != 0 {
		timeout = req.Timeout
	}
	idempotent := isIdempotent(req.Method)
	rt := c.runtime()

	attempt, retries := 0, 0
	refreshed, forceRefresh := false, false
	for {
		token, err := c.config.AccessToken.AccessToken(ctx, forceRefresh)
		if err != nil {
			return err
		}
		forceRefresh = false
		attempt++

		httpReq, err := c.newHTTPRequest(req, target, payload, contentType, token, linkedAccountID)
		if err != nil {
			return err
		}
		if c.config.OnRequest != nil {
			info := RequestInfo{Method: req.Method, URL: safeURL, Header: redactHeader(httpReq.Header), Attempt: attempt}
			callHook(func() { c.config.OnRequest(info) })
		}

		started := time.Now()
		resp, data, sendErr := c.send(ctx, httpReq, timeout)
		elapsed := time.Since(started)

		if sendErr != nil {
			sanitizeErrorURL(sendErr)
			c.afterAttempt(ResponseInfo{Method: req.Method, URL: safeURL, Duration: elapsed, Attempt: attempt, Err: sendErr})
			c.debugf("%s %s -> error (%dms): %v", req.Method, logPath, elapsed.Milliseconds(), sendErr)
			if ctx.Err() == nil && !isNetworkError(sendErr) {
				// The transport failed on purpose, not the network: surface its error unchanged.
				if urlErr, ok := sendErr.(*url.Error); ok {
					return urlErr.Err
				}
				return sendErr
			}
			connErr := &ConnectionError{Method: req.Method, URL: safeURL, Attempts: attempt, Err: sendErr}
			if ctx.Err() != nil || !idempotent || retries >= maxRetries {
				return connErr
			}
			delay := backoff(retries, rt.jitter)
			retries++
			c.debugf("retrying %s %s in %s (retry %d/%d)", req.Method, logPath, delay.Round(time.Millisecond), retries, maxRetries)
			if err := rt.sleep(ctx, delay); err != nil {
				return connErr
			}
			continue
		}

		var apiErr *APIError
		requestID := resp.Header.Get("X-Request-Id")
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			apiErr = newAPIError(resp, data)
			apiErr.Attempts = attempt
			apiErr.Operation = req.Operation
			apiErr.RequiredScope, _ = RequiredScope(req.Operation)
			requestID = apiErr.RequestID
		}
		c.afterAttempt(ResponseInfo{Method: req.Method, URL: safeURL, StatusCode: resp.StatusCode, RequestID: requestID, Duration: elapsed, Attempt: attempt})
		if requestID != "" {
			c.debugf("%s %s -> %d (%dms, %s)", req.Method, logPath, resp.StatusCode, elapsed.Milliseconds(), requestID)
		} else {
			c.debugf("%s %s -> %d (%dms)", req.Method, logPath, resp.StatusCode, elapsed.Milliseconds())
		}

		if apiErr == nil {
			if out == nil || resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(data)) == 0 {
				return nil
			}
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("ofauth: decode %s %s response: %w", req.Method, req.Path, err)
			}
			return nil
		}

		// invalid_token: refresh once and resend. Not counted as a retry.
		if resp.StatusCode == http.StatusUnauthorized && !refreshed && isRefreshable(c.config.AccessToken) && apiErr.Code == "invalid_token" {
			refreshed, forceRefresh = true, true
			continue
		}

		if retries >= maxRetries || ctx.Err() != nil || !retryableStatus(resp.StatusCode, apiErr.Code, idempotent) {
			return apiErr
		}
		delay, serverDelay := retryAfterDelay(resp.Header)
		if serverDelay && delay > c.maxRetryDelay() {
			c.debugf("not retrying %s %s: server asked to wait %s", req.Method, logPath, delay.Round(time.Second))
			return apiErr
		}
		if !serverDelay {
			delay = backoff(retries, rt.jitter)
		}
		retries++
		c.debugf("retrying %s %s in %s (retry %d/%d)", req.Method, logPath, delay.Round(time.Millisecond), retries, maxRetries)
		if err := rt.sleep(ctx, delay); err != nil {
			return apiErr
		}
	}
}

func (c *Client) newHTTPRequest(req *Request, target string, payload []byte, contentType, token, linkedAccountID string) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	httpReq, err := http.NewRequest(req.Method, target, body)
	if err != nil {
		return nil, err
	}
	// Canonical keys, so a caller's "accept" or "x-linked-account-id" is
	// replaced by the SDK's value below instead of being sent next to it.
	for _, header := range []http.Header{c.config.Header, req.Header} {
		for key, values := range header {
			httpReq.Header[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
	}
	if req.RawBody == nil {
		httpReq.Header.Set("Accept", "application/json")
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	if req.LinkedAccount {
		httpReq.Header.Set(LinkedAccountHeader, linkedAccountID)
	}
	return httpReq, nil
}

// send runs one attempt with its own timeout and reads the whole body.
func (c *Client) send(ctx context.Context, httpReq *http.Request, timeout time.Duration) (*http.Response, []byte, error) {
	attemptCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		attemptCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	client := *c.httpClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(httpReq.WithContext(attemptCtx))
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

func (c *Client) afterAttempt(info ResponseInfo) {
	if c.config.OnResponse != nil {
		callHook(func() { c.config.OnResponse(info) })
	}
}

// callHook runs a user hook, ignoring panics so a hook cannot break a request.
func callHook(fn func()) {
	defer func() { _ = recover() }()
	fn()
}

// redactHeader returns a copy of header with canonical names and credential
// values redacted, whatever the casing of their names.
func redactHeader(header http.Header) http.Header {
	out := make(http.Header, len(header))
	for name, values := range header {
		key := http.CanonicalHeaderKey(name)
		switch {
		case key == "Authorization":
			out[key] = []string{"Bearer [REDACTED]"}
		case isSensitiveHeader(key):
			out[key] = []string{"[REDACTED]"}
		default:
			out[key] = append(out[key], values...)
		}
	}
	return out
}

// isNetworkError reports whether err, from sending a request or reading its
// response, is a genuine network failure or timeout: a net.Error (including
// timeouts), io.ErrUnexpectedEOF or io.EOF (connection closed early),
// ECONNRESET, ECONNREFUSED, or the per-attempt deadline, possibly inside the
// *url.Error added by http.Client. Errors a custom http.RoundTripper returns on
// purpose are not network errors.
func isNetworkError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// *url.Error itself implements net.Error: classify its cause.
		err = urlErr.Err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func isIdempotent(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func retryableStatus(status int, code string, idempotent bool) bool {
	switch {
	case status == http.StatusTooManyRequests:
		return true
	case status == http.StatusServiceUnavailable && code == "authorization_temporarily_unavailable":
		// Rejected before execution, so safe for any method.
		return true
	case status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout:
		return idempotent
	}
	return false
}

// retryAfterDelay reads Retry-After (seconds or HTTP date), then
// RateLimit-Reset (seconds). ok is false when neither is present.
func retryAfterDelay(header http.Header) (delay time.Duration, ok bool) {
	if value := strings.TrimSpace(header.Get("Retry-After")); value != "" {
		if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 {
			return time.Duration(seconds * float64(time.Second)), true
		}
		if at, err := http.ParseTime(value); err == nil {
			return max(time.Until(at), 0), true
		}
	}
	if value := strings.TrimSpace(header.Get("RateLimit-Reset")); value != "" {
		if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 {
			return time.Duration(seconds * float64(time.Second)), true
		}
	}
	return 0, false
}

// backoff is 0.5s * 2^retry with full jitter, capped at 8s.
func backoff(retry int, jitter func() float64) time.Duration {
	ceiling := retryBaseDelay << min(retry, 10)
	if ceiling > retryMaxDelay {
		ceiling = retryMaxDelay
	}
	return time.Duration(float64(ceiling) * jitter())
}

func isRefreshable(source TokenSource) bool {
	_, static := source.(StaticToken)
	return !static
}

// ============================================================================
// Errors
// ============================================================================

// RecoveryAction says what to do after a failed call. Values not listed in
// the RecoveryAction* constants are kept as-is.
type RecoveryAction string

// Recovery actions returned in APIError.RecoveryAction and OAuthError.RecoveryAction.
const (
	RecoveryActionObtainExternalOAuthToken     RecoveryAction = "obtain_external_oauth_token"
	RecoveryActionRestartAuthorization         RecoveryAction = "restart_authorization"
	RecoveryActionReconnectLinkedAccount       RecoveryAction = "reconnect_linked_account"
	RecoveryActionSelectLinkedAccount          RecoveryAction = "select_linked_account"
	RecoveryActionGrantLinkedAccount           RecoveryAction = "grant_linked_account"
	RecoveryActionListLinkedAccounts           RecoveryAction = "list_linked_accounts"
	RecoveryActionRequestAdditionalConsent     RecoveryAction = "request_additional_consent"
	RecoveryActionEnableLinkedAccountVaultPlus RecoveryAction = "enable_linked_account_vault_plus"
	RecoveryActionEnableVaultPlus              RecoveryAction = "enable_vault_plus"
	RecoveryActionRetryAfterReset              RecoveryAction = "retry_after_reset"
	RecoveryActionRetry                        RecoveryAction = "retry"
	RecoveryActionCompleteIntegrationApproval  RecoveryAction = "complete_integration_approval"
	RecoveryActionUpdateDeveloperPlan          RecoveryAction = "update_developer_plan"
	RecoveryActionContactIntegrationOwner      RecoveryAction = "contact_integration_owner"
	RecoveryActionDoNotRepeat                  RecoveryAction = "do_not_repeat"
	RecoveryActionCheckRequest                 RecoveryAction = "check_request"
	RecoveryActionCheckResource                RecoveryAction = "check_resource"
	RecoveryActionCorrectRequest               RecoveryAction = "correct_request"
	RecoveryActionRestartUpload                RecoveryAction = "restart_upload"
)

// RecoveryActions lists every known recovery action.
var RecoveryActions = []RecoveryAction{
	RecoveryActionObtainExternalOAuthToken, RecoveryActionRestartAuthorization, RecoveryActionReconnectLinkedAccount,
	RecoveryActionSelectLinkedAccount, RecoveryActionGrantLinkedAccount, RecoveryActionListLinkedAccounts,
	RecoveryActionRequestAdditionalConsent, RecoveryActionEnableLinkedAccountVaultPlus, RecoveryActionEnableVaultPlus,
	RecoveryActionRetryAfterReset, RecoveryActionRetry, RecoveryActionCompleteIntegrationApproval,
	RecoveryActionUpdateDeveloperPlan, RecoveryActionContactIntegrationOwner, RecoveryActionDoNotRepeat,
	RecoveryActionCheckRequest, RecoveryActionCheckResource, RecoveryActionCorrectRequest,
	RecoveryActionRestartUpload,
}

// Known reports whether a is one of the RecoveryAction* constants.
func (a RecoveryAction) Known() bool {
	for _, known := range RecoveryActions {
		if a == known {
			return true
		}
	}
	return false
}

func (a RecoveryAction) needsReauthorization() bool {
	switch a {
	case RecoveryActionRestartAuthorization, RecoveryActionRequestAdditionalConsent, RecoveryActionGrantLinkedAccount:
		return true
	}
	return false
}

// ValidationIssue is one failed check from a request validation error
// (RequestValidationError).
type ValidationIssue struct {
	// Code is the validator code, e.g. "too_big".
	Code string
	// Path locates the bad value: string keys and int indexes, e.g. ["body", "items", 0].
	Path []any
	// Message is the human-readable message.
	Message string
}

// APIError is a non-2xx response from /v3/access, /v3/vault-plus, or
// /v3/linked-accounts.
//
// Branch on RecoveryAction (e.g. RecoveryActionReconnectLinkedAccount) or the
// helper methods, not on the HTTP status alone:
//
//	var apiErr *ofauth.APIError
//	if errors.As(err, &apiErr) && apiErr.NeedsReconnect() { ... }
//
// Validation failures have Code "invalid_request" and list Issues; handler
// errors ({"error": "<message>", "type": "RESOURCE_NOT_FOUND"} bodies) use the
// lower-cased type as Code and keep it in ErrorType.
type APIError struct {
	// StatusCode is the HTTP status.
	StatusCode int
	// Code is the stable machine-readable error code, e.g. "linked_account_reconnect_required",
	// "invalid_request", or "resource_not_found".
	Code string
	// Issues lists the failed checks when the request failed validation (Code "invalid_request"); nil otherwise.
	Issues []ValidationIssue
	// ErrorType is the raw error class of handler errors, e.g. "RESOURCE_NOT_FOUND"; "" otherwise.
	ErrorType string
	// Message is the human-readable message, when the API sent one.
	Message string
	// RecoveryAction says what to do next. See the V3 errors reference.
	RecoveryAction RecoveryAction
	// RequestID identifies the request (body requestId or x-request-id). Quote it in support requests.
	RequestID string
	// RetryAfter is the Retry-After delay. Zero when the header is absent.
	RetryAfter time.Duration
	// Attempts is how many HTTP attempts were made, including retries.
	Attempts int
	// Operation is the canonical name of the failed call, e.g. "access.chats.messages.send".
	Operation string
	// RequiredScope is the scope Operation needs ("" when none or unknown).
	RequiredScope Scope
	// Body is the raw response body.
	Body []byte
	// Header holds the response headers.
	Header http.Header
}

// Error implements error.
func (e *APIError) Error() string {
	msg := fmt.Sprintf("ofauth: %d %s", e.StatusCode, e.Code)
	if e.Message != "" && e.Message != e.Code {
		msg += ": " + e.Message
	}
	if e.RecoveryAction != "" {
		msg += " (recovery: " + string(e.RecoveryAction) + ")"
	}
	if e.RequestID != "" {
		msg += " [request " + e.RequestID + "]"
	}
	return msg
}

// IsRetryable reports whether trying again later can succeed: recovery
// action retry or retry_after_reset, or status 429, 502, 503, or 504.
func (e *APIError) IsRetryable() bool {
	switch e.RecoveryAction {
	case RecoveryActionRetry, RecoveryActionRetryAfterReset:
		return true
	}
	switch e.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// NeedsTokenRefresh reports recovery action obtain_external_oauth_token.
func (e *APIError) NeedsTokenRefresh() bool {
	return e.RecoveryAction == RecoveryActionObtainExternalOAuthToken
}

// NeedsReauthorization reports that the user must go through the
// authorization flow again: recovery action restart_authorization,
// request_additional_consent, or grant_linked_account.
func (e *APIError) NeedsReauthorization() bool {
	return e.RecoveryAction.needsReauthorization()
}

// NeedsReconnect reports that the account owner must reconnect the linked
// account (recovery action reconnect_linked_account).
func (e *APIError) NeedsReconnect() bool {
	return e.RecoveryAction == RecoveryActionReconnectLinkedAccount
}

// IsIntegrationProblem reports a problem with your integration rather than
// the user: complete_integration_approval, update_developer_plan,
// contact_integration_owner, or enable_vault_plus.
func (e *APIError) IsIntegrationProblem() bool {
	switch e.RecoveryAction {
	case RecoveryActionCompleteIntegrationApproval, RecoveryActionUpdateDeveloperPlan,
		RecoveryActionContactIntegrationOwner, RecoveryActionEnableVaultPlus:
		return true
	}
	return false
}

// ConnectionError means a request failed without a response because of the
// network (connection refused or reset, DNS, a dropped connection), a
// per-attempt timeout, or the caller's context, after any retries. It unwraps
// to the cause, so errors.Is(err, context.DeadlineExceeded) works. Other
// errors from a custom http.RoundTripper are returned unwrapped and never
// retried.
type ConnectionError struct {
	Method string
	// URL is the request URL without credentials (see RequestInfo.URL), so
	// the error can be logged as-is.
	URL string
	// Attempts is how many attempts were made, including retries.
	Attempts int
	// Err is the last attempt's error.
	Err error
}

// Error implements error.
func (e *ConnectionError) Error() string {
	return fmt.Sprintf("ofauth: %s %s failed after %d attempt(s): %v", e.Method, e.URL, e.Attempts, e.Err)
}

// Unwrap returns the cause.
func (e *ConnectionError) Unwrap() error { return e.Err }

func newAPIError(resp *http.Response, data []byte) *APIError {
	e := &APIError{
		StatusCode: resp.StatusCode,
		Body:       data,
		Header:     resp.Header,
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
	var envelope struct {
		Error     any `json:"error"`
		Message   any `json:"message"`
		RequestID any `json:"requestId"`
		Recovery  any `json:"recovery"`
		Type      any `json:"type"`
	}
	if json.Unmarshal(data, &envelope) == nil {
		e.Message, _ = envelope.Message.(string)
		e.RequestID, _ = envelope.RequestID.(string)
		recovery, hasRecovery := envelope.Recovery.(map[string]any)
		if hasRecovery {
			action, _ := recovery["action"].(string)
			e.RecoveryAction = RecoveryAction(action)
		}
		errorText, isText := envelope.Error.(string)
		errorType, hasType := envelope.Type.(string)
		switch {
		case parseValidationError(envelope.Error, e):
			// RequestValidationError: {"success": false, "error": {"name": "ZodError", "issues": [...]}}
		case isText && hasType && !hasRecovery:
			// AccessHandlerError: {"error": "<message>", "type": "RESOURCE_NOT_FOUND"}
			e.Code = strings.ToLower(errorType)
			e.Message = errorText
			e.ErrorType = errorType
		case isText:
			// RuntimeError: {"error": "<code>", "recovery": {"action": ...}}
			e.Code = errorText
		}
	}
	if e.Code == "" {
		e.Code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	if e.RequestID == "" {
		e.RequestID = resp.Header.Get("X-Request-Id")
	}
	return e
}

// parseValidationError fills e from a RequestValidationError "error" object
// ({"name": "ZodError", "issues": [...]}) and reports whether it was one.
func parseValidationError(raw any, e *APIError) bool {
	obj, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	_, hasName := obj["name"].(string)
	rawIssues, hasIssues := obj["issues"].([]any)
	if !hasName || !hasIssues {
		return false
	}
	e.Code = "invalid_request"
	if e.RecoveryAction == "" {
		e.RecoveryAction = RecoveryActionCheckRequest
	}
	e.Issues = []ValidationIssue{}
	parts := make([]string, 0, len(rawIssues))
	for _, raw := range rawIssues {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		issue := ValidationIssue{Path: []any{}}
		issue.Code, _ = item["code"].(string)
		issue.Message, _ = item["message"].(string)
		segments := []string{}
		if path, ok := item["path"].([]any); ok {
			for _, p := range path {
				switch v := p.(type) {
				case string:
					issue.Path = append(issue.Path, v)
					segments = append(segments, v)
				case float64:
					issue.Path = append(issue.Path, int(v))
					segments = append(segments, strconv.Itoa(int(v)))
				}
			}
		}
		e.Issues = append(e.Issues, issue)
		if len(segments) > 0 {
			parts = append(parts, strings.Join(segments, ".")+": "+issue.Message)
		} else {
			parts = append(parts, issue.Message)
		}
	}
	if len(parts) > 0 {
		e.Message = strings.Join(parts, "; ")
	}
	return true
}

// IsAPIError reports whether err is an *APIError whose Code or RecoveryAction
// equals codeOrAction. An empty codeOrAction matches any *APIError.
func IsAPIError(err error, codeOrAction string) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return codeOrAction == "" || apiErr.Code == codeOrAction || string(apiErr.RecoveryAction) == codeOrAction
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := time.Until(at); d > 0 {
			return d.Round(time.Second)
		}
	}
	return 0
}

// ============================================================================
// Helpers
// ============================================================================

// Ptr returns a pointer to v, for optional params: ofauth.Ptr(int64(20)).
func Ptr[T any](v T) *T {
	return &v
}

// Decode converts a loosely typed value (a field typed any, because its
// schema is a union of different JSON kinds) into T by re-encoding it as JSON.
func Decode[T any](v any) (T, error) {
	var out T
	data, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(data, &out)
	return out, err
}

func setQuery(q url.Values, key string, value any) {
	switch v := value.(type) {
	case nil:
	case string:
		q.Set(key, v)
	case *string:
		if v != nil {
			q.Set(key, *v)
		}
	case int64:
		q.Set(key, strconv.FormatInt(v, 10))
	case *int64:
		if v != nil {
			q.Set(key, strconv.FormatInt(*v, 10))
		}
	case float64:
		q.Set(key, strconv.FormatFloat(v, 'f', -1, 64))
	case *float64:
		if v != nil {
			q.Set(key, strconv.FormatFloat(*v, 'f', -1, 64))
		}
	case bool:
		q.Set(key, strconv.FormatBool(v))
	case *bool:
		if v != nil {
			q.Set(key, strconv.FormatBool(*v))
		}
	case []string:
		for _, item := range v {
			q.Add(key, item)
		}
	case []int64:
		for _, item := range v {
			q.Add(key, strconv.FormatInt(item, 10))
		}
	case []float64:
		for _, item := range v {
			q.Add(key, strconv.FormatFloat(item, 'f', -1, 64))
		}
	case []bool:
		for _, item := range v {
			q.Add(key, strconv.FormatBool(item))
		}
	case []any:
		for _, item := range v {
			if item != nil {
				q.Add(key, fmt.Sprint(item))
			}
		}
	default:
		q.Set(key, fmt.Sprint(v))
	}
}

// ============================================================================
// Pagination
// ============================================================================

// PageOption configures an iterator.
type PageOption func(*pageOptions)

type pageOptions struct {
	maxItems int
}

// MaxItems stops an iterator after n items. n <= 0 means no limit.
func MaxItems(n int) PageOption {
	return func(o *pageOptions) { o.maxItems = n }
}

// paginate yields every item of a cursor-paginated operation. fetch receives
// the cursor for the next page (nil for the first) and returns the page's
// items, the next cursor, and whether more pages exist. Iteration stops on
// hasMore false, an empty next cursor, an empty page, or the first error.
func paginate[T any](fetch func(cursor *string) ([]T, string, bool, error), opts []PageOption) iter.Seq2[T, error] {
	var o pageOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(yield func(T, error) bool) {
		count := 0
		var cursor *string
		for {
			items, next, more, err := fetch(cursor)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, item := range items {
				if o.maxItems > 0 && count >= o.maxItems {
					return
				}
				if !yield(item, nil) {
					return
				}
				count++
			}
			if (o.maxItems > 0 && count >= o.maxItems) || !more || next == "" || len(items) == 0 {
				return
			}
			nextCursor := next
			cursor = &nextCursor
		}
	}
}
