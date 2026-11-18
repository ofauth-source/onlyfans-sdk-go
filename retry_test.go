package ofauth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

// fakeSleeps records retry delays instead of sleeping.
type fakeSleeps struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (f *fakeSleeps) sleep(ctx context.Context, d time.Duration) error {
	f.mu.Lock()
	f.delays = append(f.delays, d)
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeSleeps) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprint(f.delays)
}

// newRetryClient returns a client whose retries record their delays (full
// jitter fixed at 1, so the delay is the backoff ceiling).
func newRetryClient(t *testing.T, config ofauth.Config) (*ofauth.Client, *fakeSleeps) {
	t.Helper()
	if config.AccessToken == nil {
		config.AccessToken = ofauth.StaticToken("tok_secret")
	}
	if config.LinkedAccountID == "" {
		config.LinkedAccountID = "conn"
	}
	client := ofauth.NewClient(config)
	sleeps := &fakeSleeps{}
	ofauth.SetRetryClock(client, sleeps.sleep, func() float64 { return 1 })
	return client, sleeps
}

// sequence answers with each response in turn, repeating the last one.
type reply struct {
	status int
	body   string
	header map[string]string
}

func sequence(replies ...reply) func(w http.ResponseWriter, r *http.Request, body []byte) {
	var mu sync.Mutex
	i := 0
	return func(w http.ResponseWriter, r *http.Request, body []byte) {
		mu.Lock()
		rep := replies[min(i, len(replies)-1)]
		i++
		mu.Unlock()
		for k, v := range rep.header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)
	}
}

const (
	transient    = `{"error":"transient_provider_failure","recovery":{"action":"retry"}}`
	authzUnavail = `{"error":"authorization_temporarily_unavailable","recovery":{"action":"retry"}}`
	okBody       = `{"id":1}`
)

func TestRetryPolicy(t *testing.T) {
	ctx := context.Background()
	getProfile := func(c *ofauth.Client) error {
		_, err := c.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{})
		return err
	}
	sendMessage := func(c *ofauth.Client) error {
		_, err := c.Access.Chats.Messages.Send(ctx, ofauth.AccessChatsMessagesSendParams{UserID: "1"})
		return err
	}

	cases := []struct {
		name       string
		call       func(*ofauth.Client) error
		replies    []reply
		maxRetries *int
		wantErr    bool
		requests   int
		delays     string
	}{
		{name: "GET 503 retried with backoff", call: getProfile, replies: []reply{{503, transient, nil}, {502, transient, nil}, {200, okBody, nil}}, requests: 3, delays: "[500ms 1s]"},
		{name: "GET 503 exhausts retries", call: getProfile, replies: []reply{{503, transient, nil}}, wantErr: true, requests: 3, delays: "[500ms 1s]"},
		{name: "POST 503 not retried", call: sendMessage, replies: []reply{{503, transient, nil}}, wantErr: true, requests: 1, delays: "[]"},
		{name: "POST 504 not retried", call: sendMessage, replies: []reply{{504, `{}`, nil}}, wantErr: true, requests: 1, delays: "[]"},
		{name: "POST 503 authorization_temporarily_unavailable retried", call: sendMessage, replies: []reply{{503, authzUnavail, nil}, {200, okBody, nil}}, requests: 2, delays: "[500ms]"},
		{name: "POST 429 honors Retry-After", call: sendMessage, replies: []reply{{429, `{"error":"rate_limited"}`, map[string]string{"Retry-After": "2"}}, {200, okBody, nil}}, requests: 2, delays: "[2s]"},
		{name: "429 honors RateLimit-Reset", call: getProfile, replies: []reply{{429, `{"error":"rate_limited"}`, map[string]string{"RateLimit-Reset": "3"}}, {200, okBody, nil}}, requests: 2, delays: "[3s]"},
		{name: "429 quota_exhausted beyond MaxRetryDelay not retried", call: getProfile, replies: []reply{{429, `{"error":"quota_exhausted","recovery":{"action":"retry_after_reset"}}`, map[string]string{"Retry-After": "3600"}}}, wantErr: true, requests: 1, delays: "[]"},
		{name: "400 not retried", call: getProfile, replies: []reply{{400, `{"error":"invalid_request"}`, nil}}, wantErr: true, requests: 1, delays: "[]"},
		{name: "500 not retried", call: getProfile, replies: []reply{{500, `{"error":"internal_error"}`, nil}}, wantErr: true, requests: 1, delays: "[]"},
		{name: "MaxRetries 0 disables retries", call: getProfile, replies: []reply{{503, transient, nil}}, maxRetries: ofauth.Ptr(0), wantErr: true, requests: 1, delays: "[]"},
		{name: "backoff capped at 8s", call: getProfile, replies: []reply{{503, transient, nil}}, maxRetries: ofauth.Ptr(6), wantErr: true, requests: 7, delays: "[500ms 1s 2s 4s 8s 8s]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, sequence(tc.replies...))
			client, sleeps := newRetryClient(t, ofauth.Config{BaseURL: ts.URL, MaxRetries: tc.maxRetries})
			err := tc.call(client)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if n := len(ts.Requests()); n != tc.requests {
				t.Fatalf("requests = %d, want %d", n, tc.requests)
			}
			if got := sleeps.String(); got != tc.delays {
				t.Fatalf("delays = %s, want %s", got, tc.delays)
			}
			var apiErr *ofauth.APIError
			if tc.wantErr && (!errors.As(err, &apiErr) || apiErr.Attempts != tc.requests) {
				t.Fatalf("Attempts: err = %#v", err)
			}
		})
	}
}

func TestRetryJitterIsFull(t *testing.T) {
	ts := newTestServer(t, sequence(reply{503, transient, nil}, reply{200, okBody, nil}))
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("t"), LinkedAccountID: "c", BaseURL: ts.URL})
	sleeps := &fakeSleeps{}
	ofauth.SetRetryClock(client, sleeps.sleep, func() float64 { return 0.25 })
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	if got := sleeps.String(); got != "[125ms]" {
		t.Fatalf("delays = %s", got)
	}
}

func TestInvalidTokenRefreshDoesNotCountAsRetry(t *testing.T) {
	var mu sync.Mutex
	step := 0
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		mu.Lock()
		step++
		n := step
		mu.Unlock()
		switch {
		case n == 1:
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
		case n <= 3:
			writeJSON(w, 503, map[string]any{"error": "transient_provider_failure"})
		default:
			writeJSON(w, 200, map[string]any{"id": 1})
		}
	})
	source := ofauth.TokenFunc(func(ctx context.Context, force bool) (string, error) { return "t", nil })
	client, sleeps := newRetryClient(t, ofauth.Config{BaseURL: ts.URL, AccessToken: source})
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if step != 4 || sleeps.String() != "[500ms 1s]" {
		t.Fatalf("steps = %d, delays = %s", step, sleeps)
	}
}

// roundTripFunc is an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNetworkErrorsRetryOnlyIdempotent(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	boom := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, boom
	})}
	client, sleeps := newRetryClient(t, ofauth.Config{BaseURL: "http://api.test", HTTPClient: httpClient})

	_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	var connErr *ofauth.ConnectionError
	if !errors.As(err, &connErr) || connErr.Attempts != 3 || !errors.Is(err, boom) || calls != 3 {
		t.Fatalf("GET: err = %v, calls = %d", err, calls)
	}
	if sleeps.String() != "[500ms 1s]" {
		t.Fatalf("delays = %s", sleeps)
	}

	calls = 0
	_, err = client.Access.Chats.Messages.Send(context.Background(), ofauth.AccessChatsMessagesSendParams{UserID: "1"})
	if !errors.As(err, &connErr) || connErr.Attempts != 1 || calls != 1 {
		t.Fatalf("POST: err = %v, calls = %d", err, calls)
	}
}

func TestNetworkErrorKindsRetried(t *testing.T) {
	kinds := map[string]error{
		"ECONNREFUSED":     syscall.ECONNREFUSED,
		"unexpected EOF":   io.ErrUnexpectedEOF,
		"dns":              &net.DNSError{Err: "no such host", Name: "api.test", IsNotFound: true},
		"wrapped timeout":  fmt.Errorf("dial: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}),
		"context deadline": context.DeadlineExceeded,
	}
	for name, cause := range kinds {
		calls := 0
		httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return nil, cause
		})}
		client, _ := newRetryClient(t, ofauth.Config{BaseURL: "http://api.test", HTTPClient: httpClient})
		_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
		var connErr *ofauth.ConnectionError
		if !errors.As(err, &connErr) || !errors.Is(err, cause) || calls != 3 {
			t.Errorf("%s: err = %v, calls = %d", name, err, calls)
		}
	}
}

// policyError is an error a custom transport returns on purpose.
type policyError struct{ reason string }

func (e *policyError) Error() string { return "policy: " + e.reason }

func TestCustomTransportErrorsAreNotRetried(t *testing.T) {
	refusal := &policyError{reason: "host not allowed"}
	plain := errors.New("transport refused")
	for _, want := range []error{refusal, plain} {
		calls := 0
		var responses []ofauth.ResponseInfo
		httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return nil, want
		})}
		client, sleeps := newRetryClient(t, ofauth.Config{
			BaseURL: "http://api.test", HTTPClient: httpClient,
			OnResponse: func(info ofauth.ResponseInfo) { responses = append(responses, info) },
		})
		_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
		var connErr *ofauth.ConnectionError
		if err != want || errors.As(err, &connErr) || calls != 1 || sleeps.String() != "[]" {
			t.Fatalf("err = %#v, calls = %d, delays = %s", err, calls, sleeps)
		}
		if len(responses) != 1 || responses[0].StatusCode != 0 || !errors.Is(responses[0].Err, want) {
			t.Fatalf("responses = %+v", responses)
		}
	}
	var policy *policyError
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("t"), LinkedAccountID: "c", BaseURL: "http://api.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, refusal })}})
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); !errors.As(err, &policy) || policy.reason != "host not allowed" {
		t.Fatalf("errors.As = %v", err)
	}
}

func TestPerAttemptTimeoutAndCancellation(t *testing.T) {
	// The transport blocks until the attempt's context ends.
	var mu sync.Mutex
	calls := 0
	block := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	client, _ := newRetryClient(t, ofauth.Config{BaseURL: "http://api.test", HTTPClient: block, Timeout: 5 * time.Millisecond})
	_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 3 {
		t.Fatalf("timeout: err = %v, calls = %d", err, calls)
	}

	// The caller's cancellation is never retried.
	calls = 0
	client, _ = newRetryClient(t, ofauth.Config{BaseURL: "http://api.test", HTTPClient: block, Timeout: -1})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			mu.Lock()
			started := calls > 0
			mu.Unlock()
			if started {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	_, err = client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancel: err = %v, calls = %d", err, calls)
	}
}

func TestUploadPartTimeout(t *testing.T) {
	var deadlines []time.Duration
	var mu sync.Mutex
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, _ := r.Context().Deadline()
		mu.Lock()
		deadlines = append(deadlines, time.Until(deadline))
		mu.Unlock()
		body := `{}`
		switch r.URL.Path {
		case "/v3/access/uploads/start":
			body = `{"status":"needs_upload","uploadId":"up_1","parts":[{"uploadUrl":"http://api.test/v3/access/uploads/up_1/parts/1","byteRange":{"start":0,"end":2}}]}`
		case "/v3/access/uploads/finalize":
			body = `{"uploads":[]}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	client, _ := newRetryClient(t, ofauth.Config{BaseURL: "http://api.test", HTTPClient: httpClient, Timeout: 10 * time.Second})
	if _, err := client.UploadMedia(context.Background(), []byte("abc"), ofauth.UploadMediaOptions{Filename: "upload.png", ContentType: "image/png"}); err != nil {
		t.Fatal(err)
	}
	if len(deadlines) != 3 || deadlines[0] > 10*time.Second || deadlines[1] < 299*time.Second || deadlines[2] > 10*time.Second {
		t.Fatalf("deadlines = %v", deadlines)
	}
}

func TestHooksAndDebugLogging(t *testing.T) {
	ts := newTestServer(t, sequence(
		reply{503, transient, map[string]string{"X-Request-Id": "req_1"}},
		reply{200, okBody, map[string]string{"X-Request-Id": "req_2"}},
	))
	var requests []ofauth.RequestInfo
	var responses []ofauth.ResponseInfo
	var lines []string
	client, _ := newRetryClient(t, ofauth.Config{
		BaseURL: ts.URL,
		OnRequest: func(info ofauth.RequestInfo) {
			requests = append(requests, info)
			panic("hooks must not break requests")
		},
		OnResponse:  func(info ofauth.ResponseInfo) { responses = append(responses, info) },
		DebugLogger: func(line string) { lines = append(lines, line) },
	})
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0].Attempt != 1 || requests[1].Attempt != 2 || requests[0].Method != "GET" ||
		!strings.HasSuffix(requests[0].URL, "/v3/access/profile") || requests[0].Header.Get("Authorization") != "Bearer [REDACTED]" {
		t.Fatalf("requests = %+v", requests)
	}
	if len(responses) != 2 || responses[0].StatusCode != 503 || responses[0].RequestID != "req_1" ||
		responses[1].StatusCode != 200 || responses[1].RequestID != "req_2" || responses[1].Attempt != 2 {
		t.Fatalf("responses = %+v", responses)
	}
	joined := strings.Join(lines, "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "[ofauth] GET /v3/access/profile -> 503 (") || !strings.HasSuffix(lines[0], ", req_1)") ||
		!strings.HasPrefix(lines[1], "[ofauth] retrying GET /v3/access/profile in 500ms (retry 1/2)") ||
		!strings.HasPrefix(lines[2], "[ofauth] GET /v3/access/profile -> 200 (") {
		t.Fatalf("lines =\n%s", joined)
	}
	if strings.Contains(joined, "tok_secret") {
		t.Fatal("debug output leaked the token")
	}
}

func TestDebugFromEnvironment(t *testing.T) {
	t.Setenv("OFAUTH_DEBUG", "1")
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	ts := newTestServer(t, sequence(reply{200, okBody, nil}))
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok_secret"), LinkedAccountID: "c", BaseURL: ts.URL})
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.HasPrefix(out, "[ofauth] GET /v3/access/profile -> 200 (") || strings.Contains(out, "tok_secret") {
		t.Fatalf("log = %q", out)
	}
}
