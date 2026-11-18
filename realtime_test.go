package ofauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

const chatEvent = `{"eventId":"evt_1","type":"realtime.chat_message.received","schemaVersion":"1","order":1,"receivedAt":"2026-01-01T00:00:00Z","environment":"live","integrationId":"int_1","linkedAccountId":"conn_1","test":false,"data":{"id":5}}`

func eventJSON(eventID string, order int, eventType string) string {
	return fmt.Sprintf(`{"eventId":%q,"type":%q,"schemaVersion":"1","order":%d,"receivedAt":"2026-01-01T00:00:00Z","environment":"live","integrationId":"int_1","linkedAccountId":"conn_1","test":false,"data":{"id":%d}}`, eventID, eventType, order, order)
}

// frame is one SSE event: id, event, and data lines.
func frame(id, event, data string) string {
	return fmt.Sprintf("id: %s\nevent: %s\ndata: %s\n\n", id, event, data)
}

func closedFrame(reason string) string {
	return fmt.Sprintf("event: closed\ndata: {\"reason\":%q}\n\n", reason)
}

// sseServer serves /v3/realtime/events with handler, which gets the 1-based
// request number. Use openStream/write to send an event stream.
func sseServer(t *testing.T, handler func(n int32, w http.ResponseWriter, r *http.Request)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(count.Add(1), w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &count
}

func openStream(w http.ResponseWriter, sessionID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	if sessionID != "" {
		w.Header().Set("X-Realtime-Session-Id", sessionID)
	}
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
}

func write(w http.ResponseWriter, s string) {
	_, _ = io.WriteString(w, s)
	w.(http.Flusher).Flush()
}

func refuse(w http.ResponseWriter, status int, code string, header map[string]string) {
	for k, v := range header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
}

// realtimeOn returns a Realtime connection from a client whose BaseURL is srv:
// Realtime always uses /v3/realtime/events on the client's BaseURL origin.
func realtimeOn(t *testing.T, srv *httptest.Server, config ofauth.Config, opts ofauth.RealtimeOptions) *ofauth.RealtimeConnection {
	t.Helper()
	config.BaseURL = srv.URL
	if config.AccessToken == nil {
		config.AccessToken = ofauth.StaticToken("tok")
	}
	if config.LinkedAccountID == "" {
		config.LinkedAccountID = "conn_1"
	}
	if opts.MaxReconnectDelay == 0 {
		opts.MaxReconnectDelay = 10 * time.Millisecond
	}
	rt, err := ofauth.NewClient(config).Realtime(opts)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// recorder collects a connection's callbacks.
type recorder struct {
	mu     sync.Mutex
	events []*ofauth.RealtimeEvent
	closes []ofauth.RealtimeCloseInfo
	errs   []error
	opens  int
	resync int
}

func record(rt *ofauth.RealtimeConnection) *recorder {
	r := &recorder{}
	rt.OnEvent(func(e *ofauth.RealtimeEvent) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() })
	rt.OnClose(func(info ofauth.RealtimeCloseInfo) { r.mu.Lock(); r.closes = append(r.closes, info); r.mu.Unlock() })
	rt.OnError(func(err error) { r.mu.Lock(); r.errs = append(r.errs, err); r.mu.Unlock() })
	rt.OnOpen(func() { r.mu.Lock(); r.opens++; r.mu.Unlock() })
	rt.OnResync(func() { r.mu.Lock(); r.resync++; r.mu.Unlock() })
	return r
}

func (r *recorder) reasons() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.closes {
		s := string(c.Reason)
		if c.Status != 0 {
			s += fmt.Sprintf("/%d", c.Status)
		}
		if c.WillReconnect {
			s += "+"
		}
		out = append(out, s)
	}
	return out
}

func waitDone(t *testing.T, rt *ofauth.RealtimeConnection) {
	t.Helper()
	select {
	case <-rt.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not stop")
	}
}

func TestRealtimeStreamsTypedEventsAndDedupes(t *testing.T) {
	var gotHeader http.Header
	var gotQuery, gotPath string
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		gotHeader, gotQuery, gotPath = r.Header.Clone(), r.URL.Query().Get("linkedAccountId"), r.URL.Path
		openStream(w, "")
		write(w, "retry: 5\n\n: heartbeat\n\n")
		write(w, frame("1", "realtime.chat_message.received", chatEvent))
		write(w, frame("2", "realtime.post.published", eventJSON("evt_2", 2, "realtime.post.published")))
		// A repeat of evt_1 (at-least-once delivery) is dropped and does not move the resume point.
		write(w, frame("3", "realtime.chat_message.received", chatEvent))
		write(w, "event: resync\ndata: {}\n\n")
		write(w, closedFrame("replaced"))
	})
	rt := realtimeOn(t, srv, ofauth.Config{Header: http.Header{"X-Trace": {"t1"}}}, ofauth.RealtimeOptions{})
	rec := record(rt)
	var typed []int64
	rt.OnRealtimeChatMessageReceived(func(e *ofauth.RealtimeEvent, d *ofauth.RealtimeChatMessageReceivedData) {
		typed = append(typed, d.ID)
	})
	var posts int
	rt.On(ofauth.EventRealtimePostPublished, func(e *ofauth.RealtimeEvent) { posts++ })

	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	if gotPath != "/v3/realtime/events" || gotQuery != "conn_1" || gotHeader.Get("Authorization") != "Bearer tok" ||
		gotHeader.Get("Accept") != "text/event-stream" || gotHeader.Get("Cache-Control") != "no-cache" ||
		gotHeader.Get("X-Trace") != "t1" || gotHeader.Get("Last-Event-ID") != "" {
		t.Fatalf("request path=%q account=%q header=%v", gotPath, gotQuery, gotHeader)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.events) != 2 || rec.events[0].EventID != "evt_1" || rec.events[1].Type != ofauth.EventRealtimePostPublished {
		t.Fatalf("events = %+v", rec.events)
	}
	if string(rec.events[0].Raw) != chatEvent || rec.events[0].Order != 1 {
		t.Fatalf("raw = %s", rec.events[0].Raw)
	}
	if len(typed) != 1 || typed[0] != 5 || posts != 1 || rec.resync != 1 || rec.opens != 1 {
		t.Fatalf("typed=%v posts=%d resync=%d opens=%d", typed, posts, rec.resync, rec.opens)
	}
	if rt.LastEventID() != "2" {
		t.Fatalf("LastEventID = %q", rt.LastEventID())
	}
	if len(rec.closes) != 1 || rec.closes[0].Reason != ofauth.RealtimeCloseReplaced || rec.closes[0].WillReconnect {
		t.Fatalf("closes = %+v", rec.closes)
	}
	if rt.Err() == nil {
		t.Fatal("expected a final error after replaced")
	}
}

func TestRealtimeResumesWithLastEventID(t *testing.T) {
	var mu sync.Mutex
	var resumes []string
	srv, count := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		resumes = append(resumes, r.Header.Get("Last-Event-ID"))
		mu.Unlock()
		openStream(w, "")
		switch n {
		case 1:
			write(w, frame("7", "realtime.chat_message.received", chatEvent))
			// The handler returns: the stream drops without a closed event.
		case 2:
			write(w, ": heartbeat\n\n")
			write(w, closedFrame("unavailable"))
		default:
			write(w, closedFrame("replaced"))
		}
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{LastEventID: "5"})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	mu.Lock()
	defer mu.Unlock()
	if count.Load() != 3 || strings.Join(resumes, ",") != "5,7,7" {
		t.Fatalf("requests=%d Last-Event-ID=%v", count.Load(), resumes)
	}
	if got := strings.Join(rec.reasons(), " "); got != "dropped+ unavailable+ replaced" {
		t.Fatalf("closes = %s", got)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.closes[0].RetryIn <= 0 || rec.closes[1].RetryIn <= 0 || rec.opens != 3 {
		t.Fatalf("closes = %+v opens=%d", rec.closes, rec.opens)
	}
}

func TestRealtimeUnavailableHonoursRetryAfter(t *testing.T) {
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		switch n {
		case 1:
			openStream(w, "")
			write(w, closedFrame("unavailable"))
		case 2:
			refuse(w, http.StatusTooManyRequests, "rate_limited", nil)
		default:
			refuse(w, http.StatusServiceUnavailable, "realtime_unavailable", map[string]string{"Retry-After": "7"})
		}
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{})
	rec := record(rt)
	rt.OnClose(func(info ofauth.RealtimeCloseInfo) {
		if info.Status == http.StatusServiceUnavailable {
			_ = rt.Close()
		}
	})
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	if got := strings.Join(rec.reasons(), " "); got != "unavailable+ unavailable/429+ unavailable/503+ client_closed" {
		t.Fatalf("closes = %s", got)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	// The backoff is capped by MaxReconnectDelay but never shorter than Retry-After.
	if rec.closes[1].RetryIn > 10*time.Millisecond || rec.closes[2].RetryIn != 7*time.Second || rec.closes[3].RetryIn != 0 {
		t.Fatalf("closes = %+v", rec.closes)
	}
	var apiErr *ofauth.APIError
	if len(rec.errs) != 2 || !errors.As(rec.errs[1], &apiErr) || apiErr.StatusCode != 503 || apiErr.RetryAfter != 7*time.Second {
		t.Fatalf("errors = %v", rec.errs)
	}
	if rt.Err() != nil {
		t.Fatalf("Err after Close = %v", rt.Err())
	}
}

func TestRealtimeReauthRefreshesTheTokenOnce(t *testing.T) {
	var mu sync.Mutex
	var forced []bool
	source := ofauth.TokenFunc(func(ctx context.Context, force bool) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		forced = append(forced, force)
		return fmt.Sprintf("tok%d", len(forced)), nil
	})
	var auths []string
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		switch n {
		case 1:
			openStream(w, "")
			write(w, closedFrame("reauth"))
		default:
			refuse(w, http.StatusUnauthorized, "invalid_token", nil)
		}
	})
	rt := realtimeOn(t, srv, ofauth.Config{AccessToken: source}, ofauth.RealtimeOptions{})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	if got := strings.Join(rec.reasons(), " "); got != "reauth+ reauth/401" {
		t.Fatalf("closes = %s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(forced) != "[false true]" || fmt.Sprint(auths) != "[Bearer tok1 Bearer tok2]" {
		t.Fatalf("forced = %v, auths = %v", forced, auths)
	}
	if rec.closes[0].Status != 0 || rec.closes[1].Status != 401 || !ofauth.IsAPIError(rt.Err(), "invalid_token") {
		t.Fatalf("closes = %+v err = %v", rec.closes, rt.Err())
	}
}

func TestRealtimeFirstConnect401(t *testing.T) {
	// A refreshable token: the first 401 forces a refresh and retries, so Connect succeeds.
	var forced []bool
	source := ofauth.TokenFunc(func(ctx context.Context, force bool) (string, error) {
		forced = append(forced, force)
		return "tok", nil
	})
	srv, count := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			refuse(w, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		openStream(w, "")
		write(w, closedFrame("replaced"))
	})
	rt := realtimeOn(t, srv, ofauth.Config{AccessToken: source}, ofauth.RealtimeOptions{})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	if got := strings.Join(rec.reasons(), " "); got != "reauth/401+ replaced" || fmt.Sprint(forced) != "[false true]" || count.Load() != 2 {
		t.Fatalf("closes = %s forced = %v requests = %d", got, forced, count.Load())
	}

	// A static token cannot be refreshed: Connect fails at once.
	static, staticCount := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		refuse(w, http.StatusUnauthorized, "invalid_token", nil)
	})
	rt = realtimeOn(t, static, ofauth.Config{}, ofauth.RealtimeOptions{})
	rec = record(rt)
	err := rt.Connect(context.Background())
	var apiErr *ofauth.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 || staticCount.Load() != 1 {
		t.Fatalf("err = %v requests = %d", err, staticCount.Load())
	}
	if got := strings.Join(rec.reasons(), " "); got != "reauth/401" {
		t.Fatalf("closes = %s", got)
	}
}

func TestRealtimeRefusalsStop(t *testing.T) {
	cases := []struct {
		name   string
		serve  func(w http.ResponseWriter)
		reason ofauth.RealtimeCloseReason
		status int
	}{
		{"409", func(w http.ResponseWriter) { refuse(w, http.StatusConflict, "stream_replaced", nil) }, ofauth.RealtimeCloseReplaced, 409},
		{"403", func(w http.ResponseWriter) { refuse(w, http.StatusForbidden, "access_token_in_browser", nil) }, ofauth.RealtimeCloseRejected, 403},
		{"404", func(w http.ResponseWriter) { refuse(w, http.StatusNotFound, "not_found", nil) }, ofauth.RealtimeCloseRejected, 404},
		{"non-SSE 200", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		}, ofauth.RealtimeCloseRejected, 200},
		{"first 503", func(w http.ResponseWriter) {
			refuse(w, http.StatusServiceUnavailable, "realtime_unavailable", map[string]string{"Retry-After": "2"})
		}, ofauth.RealtimeCloseUnavailable, 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, count := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) { tc.serve(w) })
			rt := realtimeOn(t, srv, ofauth.Config{AccessToken: ofauth.TokenFunc(func(context.Context, bool) (string, error) { return "tok", nil })}, ofauth.RealtimeOptions{})
			rec := record(rt)
			err := rt.Connect(context.Background())
			var apiErr *ofauth.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || count.Load() != 1 {
				t.Fatalf("err = %v requests = %d", err, count.Load())
			}
			waitDone(t, rt)
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.closes) != 1 || rec.closes[0].Reason != tc.reason || rec.closes[0].Status != tc.status || rec.closes[0].WillReconnect {
				t.Fatalf("closes = %+v", rec.closes)
			}
			if tc.status == 503 && apiErr.RetryAfter != 2*time.Second {
				t.Fatalf("RetryAfter = %s", apiErr.RetryAfter)
			}
		})
	}
}

func TestRealtimeHeartbeatTimeout(t *testing.T) {
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		switch n {
		case 1:
			// Opens, then goes silent.
			openStream(w, "")
			write(w, ": heartbeat\n\n")
			<-r.Context().Done()
		default:
			openStream(w, "")
			write(w, closedFrame("replaced"))
		}
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{HeartbeatTimeout: 80 * time.Millisecond})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	if got := strings.Join(rec.reasons(), " "); got != "heartbeat_timeout+ replaced" {
		t.Fatalf("closes = %s", got)
	}
	rec.mu.Lock()
	var connErr *ofauth.ConnectionError
	if rec.closes[0].RetryIn <= 0 || len(rec.errs) == 0 || !errors.As(rec.errs[0], &connErr) {
		t.Fatalf("closes = %+v errs = %v", rec.closes, rec.errs)
	}
	rec.mu.Unlock()

	// The timeout also bounds the wait for the response headers.
	silent, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	rt = realtimeOn(t, silent, ofauth.Config{}, ofauth.RealtimeOptions{HeartbeatTimeout: 50 * time.Millisecond})
	rec = record(rt)
	started := time.Now()
	if err := rt.Connect(context.Background()); !errors.As(err, &connErr) || time.Since(started) > 2*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(started))
	}
	if got := strings.Join(rec.reasons(), " "); got != "heartbeat_timeout" {
		t.Fatalf("closes = %s", got)
	}
}

func TestRealtimeIgnoresTheRequestTimeout(t *testing.T) {
	// The client's per-request timeouts do not cut the long-lived stream.
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		openStream(w, "")
		for range 6 {
			time.Sleep(25 * time.Millisecond)
			write(w, ": heartbeat\n\n")
		}
		write(w, closedFrame("replaced"))
	})
	rt := realtimeOn(t, srv, ofauth.Config{Timeout: 30 * time.Millisecond, HTTPClient: &http.Client{Timeout: 30 * time.Millisecond}}, ofauth.RealtimeOptions{})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	if got := strings.Join(rec.reasons(), " "); got != "replaced" {
		t.Fatalf("closes = %s", got)
	}
}

func TestRealtimeBadEventsAndDisableReconnect(t *testing.T) {
	srv, count := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		openStream(w, "")
		write(w, "id: 4\nevent: realtime.chat_message.received\ndata: not json\n\n")
		write(w, "id: 5\ndata: {\"eventId\":\"e5\"}\n\n")
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{DisableReconnect: true})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	// Undecodable events are reported and still move the resume point.
	if len(rec.events) != 0 || len(rec.errs) != 2 || rt.LastEventID() != "5" || count.Load() != 1 {
		t.Fatalf("events=%d errs=%v last=%q requests=%d", len(rec.events), rec.errs, rt.LastEventID(), count.Load())
	}
	if len(rec.closes) != 1 || rec.closes[0].Reason != ofauth.RealtimeCloseDropped || rec.closes[0].WillReconnect {
		t.Fatalf("closes = %+v", rec.closes)
	}
}

func TestRealtimeConnectAndClose(t *testing.T) {
	srv, count := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		openStream(w, "")
		<-r.Context().Done()
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{})
	rec := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Connect while connected is a no-op.
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = rt.Close()
	waitDone(t, rt)
	if rt.Err() != nil || count.Load() != 1 {
		t.Fatalf("Err = %v requests = %d", rt.Err(), count.Load())
	}
	if got := strings.Join(rec.reasons(), " "); got != "client_closed" {
		t.Fatalf("closes = %s", got)
	}
	// Connect after it stopped starts again.
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = rt.Close()
	waitDone(t, rt)
	if count.Load() != 2 {
		t.Fatalf("requests = %d", count.Load())
	}

	// Canceling the Connect context stops the connection too.
	ctx, cancel := context.WithCancel(context.Background())
	rt = realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{})
	rec = record(rt)
	if err := rt.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitDone(t, rt)
	if !errors.Is(rt.Err(), context.Canceled) || strings.Join(rec.reasons(), " ") != "client_closed" {
		t.Fatalf("Err = %v closes = %v", rt.Err(), rec.reasons())
	}

	if _, err := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok")}).Realtime(ofauth.RealtimeOptions{}); !errors.Is(err, ofauth.ErrLinkedAccountRequired) {
		t.Fatalf("err = %v", err)
	}
	withAuth := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", Header: http.Header{"authorization": {"Bearer x"}}})
	if _, err := withAuth.Realtime(ofauth.RealtimeOptions{}); !errors.Is(err, ofauth.ErrAuthorizationHeader) {
		t.Fatalf("err = %v", err)
	}
}

func TestRealtimeHooksAndDebug(t *testing.T) {
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("linkedAccountId") == "taken" {
			refuse(w, http.StatusConflict, "stream_replaced", nil)
			return
		}
		openStream(w, "rts_1")
		write(w, closedFrame("replaced"))
	})

	var mu sync.Mutex
	var requests []ofauth.RequestInfo
	var responses []ofauth.ResponseInfo
	var lines []string
	config := ofauth.Config{
		AccessToken: ofauth.StaticToken("tok_secret"),
		OnRequest:   func(info ofauth.RequestInfo) { mu.Lock(); requests = append(requests, info); mu.Unlock() },
		OnResponse:  func(info ofauth.ResponseInfo) { mu.Lock(); responses = append(responses, info); mu.Unlock() },
		DebugLogger: func(line string) { mu.Lock(); lines = append(lines, line); mu.Unlock() },
	}
	rt := realtimeOn(t, srv, config, ofauth.RealtimeOptions{LastEventID: "9"})
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt)
	mu.Lock()
	if len(requests) != 1 || requests[0].Method != "GET" || requests[0].Attempt != 1 || requests[0].URL != srv.URL+"/v3/realtime/events?linkedAccountId=conn_1" ||
		requests[0].Header.Get("Authorization") != "Bearer [REDACTED]" || requests[0].Header.Get("Last-Event-Id") != "9" {
		t.Fatalf("requests = %+v", requests)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 || responses[0].RequestID != "rts_1" || responses[0].Err != nil || responses[0].Attempt != 1 {
		t.Fatalf("responses = %+v", responses)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "[ofauth] SSE /v3/realtime/events -> 200 (") || !strings.HasSuffix(lines[0], "ms, rts_1)") ||
		strings.Contains(strings.Join(lines, ""), "tok_secret") {
		t.Fatalf("lines = %q", lines)
	}
	requests, responses, lines = nil, nil, nil
	mu.Unlock()

	// Refusals report the HTTP status.
	rt = realtimeOn(t, srv, config, ofauth.RealtimeOptions{LinkedAccountID: "taken"})
	if err := rt.Connect(context.Background()); !ofauth.IsAPIError(err, "stream_replaced") {
		t.Fatalf("err = %v", err)
	}
	mu.Lock()
	if len(responses) != 1 || responses[0].StatusCode != 409 || len(lines) != 1 || !strings.HasPrefix(lines[0], "[ofauth] SSE /v3/realtime/events -> 409 (") {
		t.Fatalf("responses = %+v lines = %q", responses, lines)
	}
	responses, lines = nil, nil
	mu.Unlock()

	// No server at all: status 0 with the error.
	srv.Close()
	rt = realtimeOn(t, srv, config, ofauth.RealtimeOptions{})
	err := rt.Connect(context.Background())
	var connErr *ofauth.ConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(responses) != 1 || responses[0].StatusCode != 0 || responses[0].Err == nil || !strings.Contains(lines[0], "-> network error (") {
		t.Fatalf("responses = %+v lines = %q", responses, lines)
	}
}

func TestCreateRealtimeStreamURL(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]string
	var auths []string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v3/realtime" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		auths = append(auths, r.Header.Get("Authorization"))
		if body["linkedAccountId"] == "limited" && calls == 1 {
			refuse(w, http.StatusTooManyRequests, "rate_limited", map[string]string{"Retry-After": "0"})
			return
		}
		if body["linkedAccountId"] == "bad" {
			refuse(w, http.StatusForbidden, "realtime_not_enabled", nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"url":"https://api.test/v3/realtime/events?linkedAccountId=%s&streamToken=st_1","expiresAt":"2026-01-01T00:10:00Z"}`, body["linkedAccountId"])
	}))
	t.Cleanup(srv.Close)

	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: srv.URL})
	got, err := client.CreateRealtimeStreamURL(context.Background(), ofauth.CreateRealtimeStreamURLParams{})
	if err != nil || !strings.Contains(got.URL, "linkedAccountId=conn_1") || got.ExpiresAt != "2026-01-01T00:10:00Z" {
		t.Fatalf("got = %+v err = %v", got, err)
	}
	if bodies[0]["linkedAccountId"] != "conn_1" || len(bodies[0]) != 1 || auths[0] != "Bearer tok" {
		t.Fatalf("body = %v auth = %v", bodies[0], auths)
	}

	// 429 is retried like any request.
	mu.Lock()
	calls = 0
	mu.Unlock()
	got, err = client.CreateRealtimeStreamURL(context.Background(), ofauth.CreateRealtimeStreamURLParams{LinkedAccountID: "limited"})
	if err != nil || !strings.Contains(got.URL, "linkedAccountId=limited") || calls != 2 {
		t.Fatalf("got = %+v err = %v calls = %d", got, err, calls)
	}

	_, err = client.CreateRealtimeStreamURL(context.Background(), ofauth.CreateRealtimeStreamURLParams{LinkedAccountID: "bad"})
	var apiErr *ofauth.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Code != "realtime_not_enabled" || apiErr.Operation != "realtime.createStreamUrl" {
		t.Fatalf("err = %v", err)
	}

	noAccount := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), BaseURL: srv.URL})
	if _, err := noAccount.CreateRealtimeStreamURL(context.Background(), ofauth.CreateRealtimeStreamURLParams{}); !errors.Is(err, ofauth.ErrLinkedAccountRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestRealtimeBoundsStalledErrorBody(t *testing.T) {
	srv, _ := sseServer(t, func(_ int32, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{HeartbeatTimeout: 50 * time.Millisecond})
	defer rt.Close()
	result := make(chan error, 1)
	go func() { result <- rt.Connect(context.Background()) }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stalled error response opened a stream")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled error body exceeded heartbeat timeout")
	}
}

func TestRealtimeInitialCursorSurvivesDisconnectOverHTTP(t *testing.T) {
	var mu sync.Mutex
	var cursors []string
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cursors = append(cursors, r.Header.Get("Last-Event-ID"))
		mu.Unlock()
		openStream(w, "cursor")
		switch n {
		case 1:
			write(w, "retry: 1\n\nid: 10\n\n")
		case 2:
			write(w, frame("11", "realtime.chat_message.received", eventJSON("evt_11", 11, "realtime.chat_message.received"))+frame("9", "realtime.chat_message.received", eventJSON("evt_11", 11, "realtime.chat_message.received"))+closedFrame("unavailable"))
		default:
			write(w, closedFrame("replaced"))
		}
	})
	rt := realtimeOn(t, srv, ofauth.Config{}, ofauth.RealtimeOptions{})
	defer rt.Close()
	recorder := record(rt)
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rt.Done():
	case <-time.After(time.Second):
		t.Fatal("stream did not close")
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(cursors) != "[ 10 11]" {
		t.Fatalf("resume cursors = %q", cursors)
	}
	if rt.LastEventID() != "11" || len(recorder.events) != 1 {
		t.Fatalf("cursor=%q events=%d", rt.LastEventID(), len(recorder.events))
	}
}
