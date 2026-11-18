package ofauth

// Realtime over Server-Sent Events: realtime.* events for one linked account.
// Lifecycle events (authorization.*, linked_account.*) are delivered by webhook only.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// realtimeEventsPath is the event stream path on the API origin.
	realtimeEventsPath = "/v3/realtime/events"
	// realtimeStreamURLPath mints a stream URL for a browser.
	realtimeStreamURLPath = "/v3/realtime"
	// defaultRealtimeRetry is the reconnection time until the stream sends "retry:".
	defaultRealtimeRetry = 3 * time.Second
	// DefaultRealtimeHeartbeatTimeout is three missed 15 s heartbeats. See
	// RealtimeOptions.HeartbeatTimeout.
	DefaultRealtimeHeartbeatTimeout = 45 * time.Second
	// defaultRealtimeMaxReconnectDelay caps the reconnect backoff.
	defaultRealtimeMaxReconnectDelay = 30 * time.Second
	// realtimeDedupeWindow is how many recent event ids are remembered (the
	// server's replay buffer holds 1,000 events).
	realtimeDedupeWindow = 1000
	// realtimeMaxLine bounds one SSE line, so a broken stream cannot exhaust memory.
	realtimeMaxLine = 4 << 20
)

// RealtimeCloseReason says why a Realtime stream ended.
type RealtimeCloseReason string

const (
	// RealtimeCloseReauth: the authorization no longer holds (the server sent
	// "closed" with "reauth", or answered 401). The connection forces a token
	// refresh and retries once, then stops.
	RealtimeCloseReauth RealtimeCloseReason = "reauth"
	// RealtimeCloseReplaced: a newer stream for this linked account took the
	// slot (more than 10 streams per account; the oldest is replaced), or 409.
	// The connection stops.
	RealtimeCloseReplaced RealtimeCloseReason = "replaced"
	// RealtimeCloseUnavailable: a transient outage ("closed" with
	// "unavailable", 503, 429, other 5xx). The connection backs off and resumes.
	RealtimeCloseUnavailable RealtimeCloseReason = "unavailable"
	// RealtimeCloseDropped: the stream ended without a "closed" event, or the
	// request failed on the network. The connection resumes.
	RealtimeCloseDropped RealtimeCloseReason = "dropped"
	// RealtimeCloseHeartbeatTimeout: nothing arrived, not even the 15 s
	// heartbeat, for RealtimeOptions.HeartbeatTimeout. The connection resumes.
	RealtimeCloseHeartbeatTimeout RealtimeCloseReason = "heartbeat_timeout"
	// RealtimeCloseRejected: the request was refused for good (400, 403, 404,
	// 406, a non-event-stream response, or an error from a custom transport).
	// The connection stops.
	RealtimeCloseRejected RealtimeCloseReason = "rejected"
	// RealtimeCloseClientClosed: Close was called or the Connect context ended.
	RealtimeCloseClientClosed RealtimeCloseReason = "client_closed"
)

// RealtimeEvent is one event from the stream: the realtime.* webhook envelope
// without occurredAt, authorizationId, and externalOauthClientId, plus
// receivedAt. Order is the stream's event id.
type RealtimeEvent struct {
	EventID       string `json:"eventId"`
	Type          string `json:"type"`
	SchemaVersion string `json:"schemaVersion"`
	Order         int64  `json:"order"`
	// ReceivedAt is when OFAuth received the event.
	ReceivedAt      string          `json:"receivedAt"`
	Environment     string          `json:"environment"`
	IntegrationID   string          `json:"integrationId"`
	LinkedAccountID string          `json:"linkedAccountId"`
	Test            bool            `json:"test"`
	Data            json.RawMessage `json:"data"`
	// Raw is the whole event JSON.
	Raw json.RawMessage `json:"-"`
}

// DecodeData decodes the event's data into v (e.g. *RealtimeChatMessageReceivedData).
func (e *RealtimeEvent) DecodeData(v any) error {
	return json.Unmarshal(e.Data, v)
}

// RealtimeCloseInfo describes one ended stream.
type RealtimeCloseInfo struct {
	// Reason is why the stream ended.
	Reason RealtimeCloseReason
	// Status is the HTTP status when the server refused the stream (401, 409,
	// 503, ...), else 0.
	Status int
	// WillReconnect is true when the connection will reconnect.
	WillReconnect bool
	// RetryIn is the delay before the next attempt, when WillReconnect.
	RetryIn time.Duration
}

// realtimeConfig is what Client.Realtime passes to a RealtimeConnection.
type realtimeConfig struct {
	// AccessToken for the authorization (StaticToken, TokenFunc, or caller TokenSource).
	AccessToken TokenSource
	// LinkedAccountID is the linked account to receive events for. Required.
	LinkedAccountID string
	// URL is always /v3/realtime/events on the client's BaseURL origin (realtimeURLFor).
	URL string
	// HTTPClient sends the stream request. Its Timeout is ignored for the
	// stream; HeartbeatTimeout bounds it instead.
	HTTPClient *http.Client
	// Header is the client's extra headers (never Authorization).
	Header http.Header
	// LastEventID resumes after this event id.
	LastEventID string
	// DisableReconnect turns off reconnects after drops and outages.
	DisableReconnect bool
	// MaxReconnectDelay caps the reconnect backoff. Defaults to 30s.
	MaxReconnectDelay time.Duration
	// HeartbeatTimeout: 0 uses DefaultRealtimeHeartbeatTimeout; negative disables it.
	HeartbeatTimeout time.Duration
	// OnRequest, OnResponse, and DebugLogger come from the client config.
	OnRequest   func(info RequestInfo)
	OnResponse  func(info ResponseInfo)
	Debug       bool
	DebugLogger func(line string)
}

// RealtimeOptions configures Client.Realtime.
type RealtimeOptions struct {
	// LinkedAccountID defaults to the client's.
	LinkedAccountID string
	// LastEventID resumes after this event id (an event's Order), e.g. one
	// stored before a restart. It is sent as Last-Event-ID.
	LastEventID string
	// DisableReconnect turns off reconnects after the stream drops or Realtime
	// is briefly unavailable.
	DisableReconnect bool
	// MaxReconnectDelay caps the reconnect backoff. 0 uses 30s.
	MaxReconnectDelay time.Duration
	// HeartbeatTimeout treats the stream as dead when nothing (not even the
	// 15 s heartbeat) arrives for this long, and reconnects. It also bounds the
	// wait for the response headers. 0 uses DefaultRealtimeHeartbeatTimeout
	// (45s); a negative value disables it.
	HeartbeatTimeout time.Duration
}

// Realtime returns a Realtime event stream (Server-Sent Events) for one
// linked account, using this client's token source, HTTP client, extra
// headers, OnRequest/OnResponse hooks, and debug logging. Call Connect on the
// result. Config.Timeout and HTTPClient.Timeout do not apply to the
// long-lived stream; RealtimeOptions.HeartbeatTimeout does.
//
// It is the only way to get a RealtimeConnection. It always streams
// GET /v3/realtime/events on the BaseURL origin: Realtime is served on the same
// origin as every other API route, so the token only goes where API requests
// go. It returns an error when BaseURL is not an http(s) URL or Config.Header
// sets Authorization.
//
// For a browser, mint a stream URL with CreateRealtimeStreamURL instead.
func (c *Client) Realtime(opts RealtimeOptions) (*RealtimeConnection, error) {
	linkedAccountID := opts.LinkedAccountID
	if linkedAccountID == "" {
		linkedAccountID = c.config.LinkedAccountID
	}
	if linkedAccountID == "" {
		return nil, fmt.Errorf("Realtime: %w", ErrLinkedAccountRequired)
	}
	if err := checkCallerHeaders(c.config.Header); err != nil {
		return nil, err
	}
	endpoint, err := realtimeURLFor(c.baseURL())
	if err != nil {
		return nil, err
	}
	return newRealtimeConnection(realtimeConfig{
		AccessToken:       c.config.AccessToken,
		LinkedAccountID:   linkedAccountID,
		URL:               endpoint,
		HTTPClient:        c.httpClient(),
		Header:            c.config.Header.Clone(),
		LastEventID:       opts.LastEventID,
		DisableReconnect:  opts.DisableReconnect,
		MaxReconnectDelay: opts.MaxReconnectDelay,
		HeartbeatTimeout:  opts.HeartbeatTimeout,
		OnRequest:         c.config.OnRequest,
		OnResponse:        c.config.OnResponse,
		DebugLogger:       c.runtime().logf,
	}), nil
}

// CreateRealtimeStreamURLParams are the parameters of CreateRealtimeStreamURL.
type CreateRealtimeStreamURLParams struct {
	// LinkedAccountID is the linked account to stream. Defaults to the client's.
	LinkedAccountID string
}

// RealtimeStreamURL is a stream URL for a browser (POST /v3/realtime).
type RealtimeStreamURL struct {
	// URL is the full GET /v3/realtime/events URL, carrying a stream
	// credential (not an access token).
	URL string `json:"url"`
	// ExpiresAt is when the credential expires (10 minutes, never after the
	// access token). An open stream then ends with "reauth".
	ExpiresAt string `json:"expiresAt"`
}

// CreateRealtimeStreamURL mints a stream URL for a browser (POST
// /v3/realtime). Send only the URL to the page, which opens it with
// EventSource (or connectRealtimeStream from the TypeScript SDK's
// realtime-browser entry point). The URL carries a 10-minute stream
// credential that can only read this account's Realtime events; the access
// token never leaves your server. Rate limited to 30 per minute per
// authorization. It goes through Do, so it gets the client's retries, hooks,
// and *APIError errors.
func (c *Client) CreateRealtimeStreamURL(ctx context.Context, params CreateRealtimeStreamURLParams) (*RealtimeStreamURL, error) {
	linkedAccountID := params.LinkedAccountID
	if linkedAccountID == "" {
		linkedAccountID = c.config.LinkedAccountID
	}
	if linkedAccountID == "" {
		return nil, fmt.Errorf("CreateRealtimeStreamURL: %w", ErrLinkedAccountRequired)
	}
	var out RealtimeStreamURL
	err := c.Do(ctx, &Request{
		Method:    http.MethodPost,
		Path:      realtimeStreamURLPath,
		Body:      map[string]string{"linkedAccountId": linkedAccountID},
		Operation: "realtime.createStreamUrl",
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RealtimeHandler handles one event.
type RealtimeHandler func(event *RealtimeEvent)

// RealtimeConnection is a Realtime event stream for one linked account, with
// automatic reconnects, resume (Last-Event-ID), and dedupe by EventID. Up to
// 10 streams per linked account can be open; a newer one replaces the oldest
// (RealtimeCloseReplaced). Get one from Client.Realtime; there is no way to
// create one without a client.
//
// Handlers run on the connection's goroutine, one at a time (except the
// OnClose call for Close, which runs on the goroutine calling Close); register
// them before Connect. Calling Close from a handler is fine.
//
//	rt, _ := client.Realtime(ofauth.RealtimeOptions{})
//	rt.OnRealtimeChatMessageReceived(func(e *ofauth.RealtimeEvent, d *ofauth.RealtimeChatMessageReceivedData) { ... })
//	rt.OnResync(func() { refetchEverything() })
//	if err := rt.Connect(ctx); err != nil { ... }
//	<-rt.Done()
type RealtimeConnection struct {
	config    realtimeConfig
	randFloat func() float64
	logf      func(line string)

	mu       sync.Mutex
	typed    map[string][]RealtimeHandler
	onEvent  []RealtimeHandler
	onResync []func()
	onOpen   []func()
	onClose  []func(RealtimeCloseInfo)
	onError  []func(error)

	// generation is bumped by Connect and Close; a run from an older one stops.
	generation   int
	active       bool
	cancel       context.CancelFunc
	pending      *realtimePending
	done         chan struct{}
	doneUsed     bool
	finalErr     error
	hasConnected bool
	attempt      int
	failures     int
	retry        time.Duration
	lastID       string
	seen         *eventIDWindow
}

// realtimePending is the outcome of a Connect waiting for the first open.
type realtimePending struct {
	ch  chan struct{}
	err error
}

// newRealtimeConnection returns an unconnected RealtimeConnection.
func newRealtimeConnection(config realtimeConfig) *RealtimeConnection {
	return &RealtimeConnection{
		config:    config,
		typed:     map[string][]RealtimeHandler{},
		done:      make(chan struct{}),
		randFloat: rand.Float64,
		logf:      debugLogger(config.Debug, config.DebugLogger),
		retry:     defaultRealtimeRetry,
		lastID:    config.LastEventID,
		seen:      newEventIDWindow(realtimeDedupeWindow),
	}
}

// On handles one event type (see the EventRealtime* constants and the typed
// OnRealtime* methods).
func (c *RealtimeConnection) On(eventType string, handler RealtimeHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.typed[eventType] = append(c.typed[eventType], handler)
}

// OnEvent handles every event.
func (c *RealtimeConnection) OnEvent(handler RealtimeHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEvent = append(c.onEvent, handler)
}

// OnResync is called when the resume point was older than the server's replay
// buffer (1,000 events or 15 minutes), so events were missed: refetch the
// state you show through the REST API.
func (c *RealtimeConnection) OnResync(handler func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onResync = append(c.onResync, handler)
}

// OnOpen is called each time a stream opens (including reconnects).
func (c *RealtimeConnection) OnOpen(handler func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onOpen = append(c.onOpen, handler)
}

// OnClose is called each time a stream ends.
func (c *RealtimeConnection) OnClose(handler func(RealtimeCloseInfo)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onClose = append(c.onClose, handler)
}

// OnError is called for failed attempts (*APIError, *ConnectionError),
// stream read failures, and undecodable events.
func (c *RealtimeConnection) OnError(handler func(error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onError = append(c.onError, handler)
}

// LastEventID is the id (Order) of the last event received, sent as
// Last-Event-ID on reconnects. Store it to resume after a restart
// (RealtimeOptions.LastEventID).
func (c *RealtimeConnection) LastEventID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastID
}

// Connect opens the stream and returns once it is open. A first attempt that
// fails returns the error (an *APIError with StatusCode and RetryAfter for a
// refused stream, e.g. 401, 409, or 503; a *ConnectionError for network
// failures) instead of retrying, except that a 401 or "reauth" first forces
// one token refresh and retries.
//
// Events are then delivered from a background goroutine until Close is
// called, ctx is canceled, or the stream stops for good (reauth after the
// retry, replaced, rejected, or a drop with DisableReconnect). Done is closed
// then. Calling Connect while connected (or connecting) waits for that
// connection instead of opening another; calling it after the connection
// stopped starts it again.
func (c *RealtimeConnection) Connect(ctx context.Context) error {
	if c.config.LinkedAccountID == "" {
		return fmt.Errorf("realtime: %w", ErrLinkedAccountRequired)
	}
	if c.config.AccessToken == nil {
		return ErrNoAccessToken
	}
	c.mu.Lock()
	if c.active {
		pending := c.pending
		c.mu.Unlock()
		if pending == nil {
			return nil
		}
		select {
		case <-pending.ch:
			return pending.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.generation++
	generation := c.generation
	c.active = true
	c.hasConnected = false
	c.attempt = 0
	c.failures = 0
	if c.doneUsed {
		c.done = make(chan struct{})
	}
	c.doneUsed = true
	c.finalErr = nil
	done := c.done
	pending := &realtimePending{ch: make(chan struct{})}
	c.pending = pending
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.mu.Unlock()

	go c.run(runCtx, generation, done)
	<-pending.ch
	return pending.err
}

// Close ends the stream and stops reconnecting. OnClose gets
// RealtimeCloseClientClosed; Done is closed once the goroutine has stopped,
// and Err is nil.
func (c *RealtimeConnection) Close() error {
	c.mu.Lock()
	if !c.active {
		c.mu.Unlock()
		return nil
	}
	c.generation++
	c.active = false
	c.finalErr = nil
	cancel := c.cancel
	c.settleLocked(errors.New("ofauth: realtime connection closed before it opened"))
	c.mu.Unlock()
	cancel()
	c.emitClose(RealtimeCloseInfo{Reason: RealtimeCloseClientClosed})
	return nil
}

// Done is closed when the connection stops for good.
func (c *RealtimeConnection) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

// Err returns why the connection stopped: nil after Close, otherwise the
// final error (e.g. an *APIError for a 409, or ctx.Err()). Valid after Done is
// closed.
func (c *RealtimeConnection) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.finalErr
}

// settleLocked resolves a waiting Connect. c.mu must be held.
func (c *RealtimeConnection) settleLocked(err error) {
	if pending := c.pending; pending != nil {
		c.pending = nil
		pending.err = err
		close(pending.ch)
	}
}

func (c *RealtimeConnection) current(generation int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation == generation
}

// realtimeOutcome is how one stream attempt ended.
type realtimeOutcome struct {
	reason     RealtimeCloseReason
	status     int
	err        error
	retryAfter time.Duration
	// healthy: the stream delivered an event or a heartbeat.
	healthy bool
}

func (c *RealtimeConnection) run(ctx context.Context, generation int, done chan struct{}) {
	// One forced token refresh (and retry) per reauth / 401, until a stream is healthy again.
	refresh, refreshUsed := false, false
	for first := true; ; first = false {
		var out realtimeOutcome
		if !first && ctx.Err() != nil {
			// ctx ended during the backoff: no further attempt.
			out = realtimeOutcome{reason: RealtimeCloseClientClosed, err: ctx.Err()}
		} else {
			out = c.stream(ctx, generation, refresh)
		}
		refresh = false

		c.mu.Lock()
		if c.generation != generation {
			c.mu.Unlock()
			close(done)
			return
		}
		if out.healthy {
			c.failures = 0
			refreshUsed = false
		}
		willReconnect := false
		var delay time.Duration
		switch out.reason {
		case RealtimeCloseReauth:
			// A static token cannot be refreshed, so a 401 for it is final.
			canRetry := !(out.status == http.StatusUnauthorized && !isRefreshable(c.config.AccessToken))
			if !refreshUsed && canRetry {
				refreshUsed, refresh, willReconnect = true, true, true
				c.failures++
			}
		case RealtimeCloseUnavailable, RealtimeCloseDropped, RealtimeCloseHeartbeatTimeout:
			willReconnect = !c.config.DisableReconnect
			if willReconnect {
				delay = c.backoffLocked(out.retryAfter)
			}
		}
		// A first Connect that never opened returns the error instead of
		// retrying in the background, except for the one token refresh.
		if !c.hasConnected && !refresh {
			willReconnect = false
		}
		final := out.err
		if final == nil {
			final = fmt.Errorf("ofauth: realtime stream closed (%s)", out.reason)
		}
		if !willReconnect {
			c.active = false
			c.finalErr = final
			c.settleLocked(final)
		}
		c.mu.Unlock()

		info := RealtimeCloseInfo{Reason: out.reason, Status: out.status, WillReconnect: willReconnect}
		if willReconnect {
			info.RetryIn = delay
		}
		c.emitClose(info)
		if !willReconnect {
			close(done)
			return
		}
		if delay > 0 {
			_ = sleepContext(ctx, delay) // a canceled ctx ends the next attempt as client_closed
		}
	}
}

// backoffLocked is exponential backoff from the server's retry time, with
// jitter, capped, and at least Retry-After. c.mu must be held.
func (c *RealtimeConnection) backoffLocked(retryAfter time.Duration) time.Duration {
	maxDelay := c.config.MaxReconnectDelay
	if maxDelay <= 0 {
		maxDelay = defaultRealtimeMaxReconnectDelay
	}
	base := min(maxDelay, c.retry<<min(c.failures, 20))
	if base <= 0 { // overflow
		base = maxDelay
	}
	c.failures++
	delay := min(maxDelay, time.Duration(float64(base)*(1+c.randFloat()/2)))
	return max(delay, retryAfter)
}

func (c *RealtimeConnection) heartbeatTimeout() time.Duration {
	switch d := c.config.HeartbeatTimeout; {
	case d == 0:
		return DefaultRealtimeHeartbeatTimeout
	case d < 0:
		return 0
	default:
		return d
	}
}

var errRealtimeHeartbeat = errors.New("ofauth: realtime stream silent")

// stream runs one attempt: request the stream, then read it until it ends.
func (c *RealtimeConnection) stream(ctx context.Context, generation int, refresh bool) realtimeOutcome {
	c.mu.Lock()
	c.attempt++
	attempt := c.attempt
	lastID := c.lastID
	c.mu.Unlock()

	token, err := c.config.AccessToken.AccessToken(ctx, refresh)
	if err != nil {
		if ctx.Err() != nil || !c.current(generation) {
			return realtimeOutcome{reason: RealtimeCloseClientClosed, err: ctx.Err()}
		}
		c.emitError(err)
		return realtimeOutcome{reason: RealtimeCloseDropped, err: err}
	}

	u, err := url.Parse(c.config.URL)
	if err != nil {
		return realtimeOutcome{reason: RealtimeCloseRejected, err: fmt.Errorf("ofauth: realtime URL: %w", err)}
	}
	q := u.Query()
	q.Set("linkedAccountId", c.config.LinkedAccountID)
	u.RawQuery = q.Encode()
	target := u.String()
	safeURL := sanitizeURL(target)

	attemptCtx, cancelAttempt := context.WithCancelCause(ctx)
	defer cancelAttempt(nil)
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, target, nil)
	if err != nil {
		return realtimeOutcome{reason: RealtimeCloseRejected, err: err}
	}
	for key, values := range c.config.Header {
		req.Header[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Authorization", "Bearer "+token)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	if c.config.OnRequest != nil {
		info := RequestInfo{Method: http.MethodGet, URL: safeURL, Header: redactHeader(req.Header), Attempt: attempt}
		callHook(func() { c.config.OnRequest(info) })
	}

	// The heartbeat timer bounds the wait for the headers and every gap between chunks.
	heartbeat := c.heartbeatTimeout()
	var timedOut atomic.Bool
	var timer *time.Timer
	if heartbeat > 0 {
		timer = time.AfterFunc(heartbeat, func() {
			timedOut.Store(true)
			cancelAttempt(errRealtimeHeartbeat)
		})
	}
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
	}
	defer stopTimer()
	arm := func() {
		if timer != nil {
			timer.Reset(heartbeat)
		}
	}

	client := *c.config.HTTPClient
	client.Timeout = 0 // the stream is long-lived; the heartbeat timer bounds it
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		stopTimer()
		sanitizeErrorURL(err)
		c.afterAttempt(ResponseInfo{Method: http.MethodGet, URL: safeURL, Duration: elapsed, Attempt: attempt, Err: err})
		if !c.current(generation) || ctx.Err() != nil {
			return realtimeOutcome{reason: RealtimeCloseClientClosed, err: &ConnectionError{Method: http.MethodGet, URL: safeURL, Attempts: attempt, Err: err}}
		}
		var outcome realtimeOutcome
		switch {
		case timedOut.Load():
			c.logLine("timeout", 0, "", elapsed)
			outcome = realtimeOutcome{reason: RealtimeCloseHeartbeatTimeout, err: &ConnectionError{Method: http.MethodGet, URL: safeURL, Attempts: attempt, Err: fmt.Errorf("no response in %s: %w", heartbeat, errRealtimeHeartbeat)}}
		case isNetworkError(err):
			c.logLine("network error", 0, "", elapsed)
			outcome = realtimeOutcome{reason: RealtimeCloseDropped, err: &ConnectionError{Method: http.MethodGet, URL: safeURL, Attempts: attempt, Err: err}}
		default:
			// The transport failed on purpose, not the network: final, with its error unchanged.
			c.logLine("error", 0, "", elapsed)
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = urlErr.Err
			}
			outcome = realtimeOutcome{reason: RealtimeCloseRejected, err: err}
		}
		c.emitError(outcome.err)
		return outcome
	}
	defer resp.Body.Close()

	requestID := resp.Header.Get("X-Realtime-Session-Id")
	if requestID == "" {
		requestID = resp.Header.Get("X-Request-Id")
	}
	c.afterAttempt(ResponseInfo{Method: http.MethodGet, URL: safeURL, StatusCode: resp.StatusCode, RequestID: requestID, Duration: elapsed, Attempt: attempt})
	c.logLine("", resp.StatusCode, requestID, elapsed)

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(contentType, "text/event-stream") {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		apiErr := newAPIError(resp, data)
		apiErr.Attempts = attempt
		apiErr.Operation = "realtime"
		if !c.current(generation) || ctx.Err() != nil {
			return realtimeOutcome{reason: RealtimeCloseClientClosed, err: apiErr}
		}
		c.emitError(apiErr)
		reason := RealtimeCloseRejected
		switch status := resp.StatusCode; {
		case status == http.StatusUnauthorized:
			reason = RealtimeCloseReauth
		case status == http.StatusConflict:
			reason = RealtimeCloseReplaced
		case status == http.StatusTooManyRequests || status >= 500:
			reason = RealtimeCloseUnavailable
		}
		return realtimeOutcome{reason: reason, status: resp.StatusCode, err: apiErr, retryAfter: apiErr.RetryAfter}
	}

	// Open.
	c.mu.Lock()
	if c.generation != generation {
		c.mu.Unlock()
		stopTimer()
		return realtimeOutcome{reason: RealtimeCloseClientClosed}
	}
	c.attempt = 0
	c.hasConnected = true
	c.settleLocked(nil)
	openHandlers := append([]func(){}, c.onOpen...)
	c.mu.Unlock()
	for _, h := range openHandlers {
		h()
	}

	var closed RealtimeCloseReason
	healthy := false
	parser := newSSEParser(lastID)
	parser.onRetry = func(ms int) {
		c.mu.Lock()
		c.retry = time.Duration(ms) * time.Millisecond
		c.mu.Unlock()
	}
	parser.onComment = func(string) { healthy = true }
	parser.onCursor = func(id string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if closed == "" && c.generation == generation {
			c.lastID = id
		}
	}
	parser.onMessage = func(msg sseMessage) {
		if closed != "" || !c.current(generation) {
			return
		}
		switch msg.event {
		case "closed":
			closed = parseRealtimeCloseReason(msg.data)
		case "resync":
			healthy = true
			c.emitResync()
		default:
			healthy = true
			c.handleEvent(msg)
		}
	}

	var failure error
	buf := make([]byte, 32<<10)
	for closed == "" && c.current(generation) {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			arm()
			if err := parser.push(buf[:n]); err != nil {
				failure = err
				break
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				failure = readErr
			}
			break
		}
	}
	stopTimer()
	parser.end()

	switch {
	case !c.current(generation):
		return realtimeOutcome{reason: RealtimeCloseClientClosed, healthy: healthy}
	case closed != "":
		return realtimeOutcome{reason: closed, healthy: healthy}
	case timedOut.Load():
		err := &ConnectionError{Method: http.MethodGet, URL: safeURL, Attempts: attempt, Err: fmt.Errorf("%w for %s", errRealtimeHeartbeat, heartbeat)}
		c.emitError(err)
		return realtimeOutcome{reason: RealtimeCloseHeartbeatTimeout, healthy: healthy, err: err}
	case ctx.Err() != nil:
		return realtimeOutcome{reason: RealtimeCloseClientClosed, healthy: healthy, err: ctx.Err()}
	}
	if failure != nil {
		c.emitError(failure)
	}
	return realtimeOutcome{reason: RealtimeCloseDropped, healthy: healthy, err: failure}
}

// afterAttempt reports one attempt to OnResponse.
func (c *RealtimeConnection) afterAttempt(info ResponseInfo) {
	if c.config.OnResponse != nil {
		callHook(func() { c.config.OnResponse(info) })
	}
}

// logLine writes e.g. "[ofauth] SSE /v3/realtime/events -> 200 (85ms, <session id>)".
func (c *RealtimeConnection) logLine(outcome string, status int, requestID string, elapsed time.Duration) {
	if c.logf == nil {
		return
	}
	if outcome == "" {
		outcome = strconv.Itoa(status)
	}
	suffix := ""
	if requestID != "" {
		suffix = ", " + requestID
	}
	line := fmt.Sprintf("[ofauth] SSE %s -> %s (%dms%s)", realtimeEventsPath, outcome, elapsed.Milliseconds(), suffix)
	callHook(func() { c.logf(line) })
}

func (c *RealtimeConnection) handleEvent(msg sseMessage) {
	var event RealtimeEvent
	err := json.Unmarshal([]byte(msg.data), &event)
	if err == nil && event.Type == "" {
		err = fmt.Errorf("ofauth: realtime event without a type (SSE event %s)", msg.event)
	} else if err != nil {
		err = fmt.Errorf("ofauth: realtime event: %w", err)
	}
	c.mu.Lock()
	if err != nil {
		if msg.lastEventID != "" {
			c.lastID = msg.lastEventID
		}
		c.mu.Unlock()
		c.emitError(err)
		return
	}
	// A repeat (at-least-once delivery) does not move the resume point back.
	if event.EventID != "" && !c.seen.add(event.EventID) {
		c.mu.Unlock()
		return
	}
	if msg.lastEventID != "" {
		c.lastID = msg.lastEventID
	}
	handlers := append(append([]RealtimeHandler{}, c.onEvent...), c.typed[event.Type]...)
	c.mu.Unlock()
	event.Raw = json.RawMessage(msg.data)
	for _, h := range handlers {
		h(&event)
	}
}

func (c *RealtimeConnection) emitResync() {
	c.mu.Lock()
	handlers := append([]func(){}, c.onResync...)
	c.mu.Unlock()
	for _, h := range handlers {
		h()
	}
}

func (c *RealtimeConnection) emitClose(info RealtimeCloseInfo) {
	c.mu.Lock()
	handlers := append([]func(RealtimeCloseInfo){}, c.onClose...)
	c.mu.Unlock()
	for _, h := range handlers {
		h(info)
	}
}

func (c *RealtimeConnection) emitError(err error) {
	c.mu.Lock()
	handlers := append([]func(error){}, c.onError...)
	c.mu.Unlock()
	for _, h := range handlers {
		h(err)
	}
}

// parseRealtimeCloseReason reads the reason of an "event: closed" frame;
// anything unknown counts as unavailable.
func parseRealtimeCloseReason(data string) RealtimeCloseReason {
	var body struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal([]byte(data), &body) == nil {
		switch r := RealtimeCloseReason(body.Reason); r {
		case RealtimeCloseReauth, RealtimeCloseReplaced, RealtimeCloseUnavailable:
			return r
		}
	}
	return RealtimeCloseUnavailable
}

// eventIDWindow remembers the most recent event ids.
type eventIDWindow struct {
	ids  map[string]struct{}
	ring []string
	next int
}

func newEventIDWindow(size int) *eventIDWindow {
	return &eventIDWindow{ids: make(map[string]struct{}, size), ring: make([]string, size)}
}

// add reports whether id is new.
func (w *eventIDWindow) add(id string) bool {
	if _, ok := w.ids[id]; ok {
		return false
	}
	if old := w.ring[w.next]; old != "" {
		delete(w.ids, old)
	}
	w.ring[w.next] = id
	w.next = (w.next + 1) % len(w.ring)
	w.ids[id] = struct{}{}
	return true
}

// sseMessage is one dispatched SSE event.
type sseMessage struct {
	// event is the "event" field, or "message" when there was none.
	event string
	// data is the "data" lines joined with "\n".
	data string
	// lastEventID is the stream's last event id at dispatch (the "id" field
	// persists across events).
	lastEventID string
}

// sseParser is an incremental Server-Sent Events parser, per the HTML "event
// stream" interpretation rules. Feed bytes with push in chunks of any size:
// lines may be split anywhere, including between "\r" and "\n". Lines end with
// "\n", "\r\n", or "\r"; a leading BOM is dropped.
type sseParser struct {
	onMessage func(sseMessage)
	onRetry   func(ms int)
	onComment func(text string)
	onCursor  func(id string)

	lastEventID string
	buf         []byte
	started     bool
	skipLF      bool
	eventType   string
	data        strings.Builder
	hasData     bool
	idBuffer    string
	hasID       bool
}

func newSSEParser(lastEventID string) *sseParser {
	return &sseParser{lastEventID: lastEventID, idBuffer: lastEventID}
}

var errSSELineTooLong = errors.New("ofauth: realtime stream line too long")

func (p *sseParser) push(chunk []byte) error {
	for len(chunk) > 0 {
		if p.skipLF {
			p.skipLF = false
			if chunk[0] == '\n' {
				chunk = chunk[1:]
				continue
			}
		}
		i := bytes.IndexAny(chunk, "\r\n")
		if i < 0 {
			if len(p.buf)+len(chunk) > realtimeMaxLine {
				return errSSELineTooLong
			}
			p.buf = append(p.buf, chunk...)
			return nil
		}
		line := string(p.buf) + string(chunk[:i])
		p.buf = p.buf[:0]
		if chunk[i] == '\r' {
			if i+1 < len(chunk) {
				if chunk[i+1] == '\n' {
					i++
				}
			} else {
				p.skipLF = true
			}
		}
		chunk = chunk[i+1:]
		p.line(line)
	}
	return nil
}

// end discards an event without its closing blank line, as the spec requires.
func (p *sseParser) end() {
	p.buf = p.buf[:0]
	p.eventType = ""
	p.data.Reset()
	p.hasData = false
	p.hasID = false
	p.idBuffer = p.lastEventID
}

func (p *sseParser) line(line string) {
	if !p.started {
		p.started = true
		line = strings.TrimPrefix(line, "\uFEFF")
	}
	if line == "" {
		p.dispatch()
		return
	}
	if line[0] == ':' {
		if p.onComment != nil {
			p.onComment(strings.TrimPrefix(line[1:], " "))
		}
		return
	}
	field, value, found := strings.Cut(line, ":")
	if found {
		value = strings.TrimPrefix(value, " ")
	}
	switch field {
	case "event":
		p.eventType = value
	case "data":
		if p.hasData {
			p.data.WriteByte('\n')
		}
		p.data.WriteString(value)
		p.hasData = true
	case "id":
		if !strings.Contains(value, "\x00") {
			p.idBuffer = value
			p.hasID = true
		}
	case "retry":
		if value != "" && strings.Trim(value, "0123456789") == "" {
			if ms, err := strconv.Atoi(value); err == nil && p.onRetry != nil {
				p.onRetry(ms)
			}
		}
	}
}

func (p *sseParser) dispatch() {
	p.lastEventID = p.idBuffer
	hasData := p.hasData
	hasID := p.hasID
	p.hasID = false
	msg := sseMessage{event: p.eventType, data: p.data.String(), lastEventID: p.lastEventID}
	if msg.event == "" {
		msg.event = "message"
	}
	p.eventType = ""
	p.data.Reset()
	p.hasData = false
	if hasData && p.onMessage != nil {
		p.onMessage(msg)
	} else if !hasData && hasID && p.onCursor != nil {
		p.onCursor(p.lastEventID)
	}
}
