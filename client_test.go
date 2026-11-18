package ofauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

// recorded is one request seen by a test server.
type recorded struct {
	Method string
	Path   string
	Query  map[string][]string
	Header http.Header
	Body   []byte
}

// testServer answers each request with handler and records it.
type testServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recorded
}

func newTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body []byte)) *testServer {
	t.Helper()
	ts := &testServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts.mu.Lock()
		ts.requests = append(ts.requests, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body})
		ts.mu.Unlock()
		handler(w, r, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *testServer) Requests() []recorded {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]recorded(nil), ts.requests...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestBearerAndLinkedAccountHeaders(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, 200, map[string]any{"id": 1})
	})
	client := ofauth.NewClient(ofauth.Config{
		AccessToken:     ofauth.StaticToken("tok_123"),
		LinkedAccountID: "conn_default",
		BaseURL:         ts.URL,
	})
	ctx := context.Background()

	if _, err := client.Access.Chats.Messages.Send(ctx, ofauth.AccessChatsMessagesSendParams{
		UserID: "42",
		Body:   ofauth.AccessChatsMessagesSendBody{Text: ofauth.Ptr("hi")},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{LinkedAccountID: "conn_override"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WithLinkedAccount("conn_other").Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.LinkedAccounts.List(ctx, ofauth.LinkedAccountsListParams{Limit: ofauth.Ptr(int64(5))}); err != nil {
		t.Fatal(err)
	}

	reqs := ts.Requests()
	if len(reqs) != 4 {
		t.Fatalf("got %d requests", len(reqs))
	}
	send := reqs[0]
	if send.Method != "POST" || send.Path != "/v3/access/chats/42/messages" {
		t.Fatalf("send: %s %s", send.Method, send.Path)
	}
	if got := send.Header.Get("Authorization"); got != "Bearer tok_123" {
		t.Fatalf("authorization = %q", got)
	}
	if got := send.Header.Get("x-linked-account-id"); got != "conn_default" {
		t.Fatalf("linked account = %q", got)
	}
	if got := send.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q", got)
	}
	if string(send.Body) != `{"text":"hi"}` {
		t.Fatalf("body = %s", send.Body)
	}
	if got := reqs[1].Header.Get("x-linked-account-id"); got != "conn_override" {
		t.Fatalf("override linked account = %q", got)
	}
	if got := reqs[2].Header.Get("x-linked-account-id"); got != "conn_other" {
		t.Fatalf("WithLinkedAccount = %q", got)
	}
	if got := reqs[3].Header.Get("x-linked-account-id"); got != "" {
		t.Fatalf("linked-accounts must not send x-linked-account-id, got %q", got)
	}
	if got := reqs[3].Query["limit"]; len(got) != 1 || got[0] != "5" {
		t.Fatalf("limit query = %v", got)
	}
}

func TestMissingLinkedAccount(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, 200, map[string]any{})
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), BaseURL: ts.URL})
	_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	if !errors.Is(err, ofauth.ErrLinkedAccountRequired) {
		t.Fatalf("err = %v", err)
	}
	if n := len(ts.Requests()); n != 0 {
		t.Fatalf("sent %d requests", n)
	}
	// Linked-accounts operations do not need one.
	if _, err := client.LinkedAccounts.List(context.Background(), ofauth.LinkedAccountsListParams{}); err != nil {
		t.Fatal(err)
	}
}

func TestMissingPathParam(t *testing.T) {
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn", BaseURL: "http://127.0.0.1:1"})
	_, err := client.Access.Chats.Messages.Send(context.Background(), ofauth.AccessChatsMessagesSendParams{})
	if err == nil || err.Error() != "ofauth: UserID is required" {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidTokenRetry(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("Authorization") != "Bearer fresh" {
			writeJSON(w, 401, map[string]any{"error": "invalid_token", "recovery": map[string]any{"action": "refresh_access_token"}})
			return
		}
		writeJSON(w, 200, map[string]any{"id": 1})
	})

	var calls []bool
	source := ofauth.TokenFunc(func(ctx context.Context, force bool) (string, error) {
		calls = append(calls, force)
		if force {
			return "fresh", nil
		}
		return "stale", nil
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: source, LinkedAccountID: "conn", BaseURL: ts.URL})
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(calls) != "[false true]" {
		t.Fatalf("token calls = %v", calls)
	}

	// A static token is not retried.
	static := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("stale"), LinkedAccountID: "conn", BaseURL: ts.URL})
	before := len(ts.Requests())
	_, err := static.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	if !ofauth.IsAPIError(err, "invalid_token") {
		t.Fatalf("err = %v", err)
	}
	if n := len(ts.Requests()) - before; n != 1 {
		t.Fatalf("static token sent %d requests", n)
	}
}

func TestAPIErrorParsing(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.URL.Path == "/v3/access/profile" {
			w.Header().Set("Retry-After", "7")
			writeJSON(w, 429, map[string]any{
				"error":     "rate_limited",
				"message":   "Slow down",
				"recovery":  map[string]any{"action": "retry_later"},
				"requestId": "req_body",
			})
			return
		}
		w.Header().Set("X-Request-Id", "req_header")
		writeJSON(w, 409, map[string]any{"error": "linked_account_reconnect_required", "recovery": map[string]any{"action": "reconnect_linked_account"}})
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn", BaseURL: ts.URL, MaxRetries: ofauth.Ptr(0)})

	_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	var apiErr *ofauth.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v", err)
	}
	if apiErr.StatusCode != 429 || apiErr.Code != "rate_limited" || apiErr.RecoveryAction != "retry_later" ||
		apiErr.RequestID != "req_body" || apiErr.RetryAfter != 7*time.Second || apiErr.Message != "Slow down" ||
		apiErr.Attempts != 1 || apiErr.Operation != "access.profile.get" || apiErr.RequiredScope != ofauth.ScopeProfileRead {
		t.Fatalf("apiErr = %+v", apiErr)
	}
	if len(apiErr.Body) == 0 {
		t.Fatal("missing raw body")
	}

	_, err = client.Access.Chats.List(context.Background(), ofauth.AccessChatsListParams{})
	if !errors.As(err, &apiErr) || apiErr.RequestID != "req_header" || apiErr.RecoveryAction != "reconnect_linked_account" {
		t.Fatalf("err = %v", err)
	}
	if !ofauth.IsAPIError(err, "reconnect_linked_account") || ofauth.IsAPIError(err, "other") {
		t.Fatal("IsAPIError mismatch")
	}
}

func TestAPIErrorShapes(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		switch r.URL.Path {
		case "/v3/access/profile": // RuntimeError
			writeJSON(w, 403, map[string]any{
				"error":     "missing_scope",
				"recovery":  map[string]any{"action": "request_additional_consent"},
				"requestId": "req_1",
			})
		case "/v3/access/chats": // RequestValidationError
			w.Header().Set("X-Request-Id", "req_2")
			writeJSON(w, 400, map[string]any{
				"success": false,
				"error": map[string]any{
					"name": "ZodError",
					"issues": []any{
						map[string]any{"code": "too_big", "path": []any{"limit"}, "message": "Number must be less than or equal to 100"},
						map[string]any{"code": "invalid_type", "path": []any{"body", "items", 0}, "message": "Required"},
					},
				},
			})
		default: // AccessHandlerError
			writeJSON(w, 404, map[string]any{"error": "Upload not found", "type": "RESOURCE_NOT_FOUND", "requestId": "req_3", "success": false})
		}
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn", BaseURL: ts.URL, MaxRetries: ofauth.Ptr(0)})
	ctx := context.Background()
	var apiErr *ofauth.APIError

	_, err := client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{})
	if !errors.As(err, &apiErr) || apiErr.Code != "missing_scope" || apiErr.RecoveryAction != ofauth.RecoveryActionRequestAdditionalConsent ||
		apiErr.RequestID != "req_1" || apiErr.Issues != nil || apiErr.ErrorType != "" || !apiErr.NeedsReauthorization() {
		t.Fatalf("runtime error = %+v", apiErr)
	}

	_, err = client.Access.Chats.List(ctx, ofauth.AccessChatsListParams{})
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_request" || apiErr.RecoveryAction != ofauth.RecoveryActionCheckRequest ||
		apiErr.RequestID != "req_2" || apiErr.ErrorType != "" || apiErr.IsRetryable() {
		t.Fatalf("validation error = %+v", apiErr)
	}
	if apiErr.Message != "limit: Number must be less than or equal to 100; body.items.0: Required" {
		t.Fatalf("validation message = %q", apiErr.Message)
	}
	if got := fmt.Sprintf("%+v", apiErr.Issues); got != "[{Code:too_big Path:[limit] Message:Number must be less than or equal to 100} {Code:invalid_type Path:[body items 0] Message:Required}]" {
		t.Fatalf("issues = %s", got)
	}
	if idx, ok := apiErr.Issues[1].Path[2].(int); !ok || idx != 0 {
		t.Fatalf("index path segment = %#v", apiErr.Issues[1].Path[2])
	}
	if len(apiErr.Body) == 0 {
		t.Fatal("missing raw body")
	}

	_, err = client.LinkedAccounts.List(ctx, ofauth.LinkedAccountsListParams{})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 || apiErr.Code != "resource_not_found" || apiErr.ErrorType != "RESOURCE_NOT_FOUND" ||
		apiErr.Message != "Upload not found" || apiErr.RecoveryAction != "" || apiErr.RequestID != "req_3" || apiErr.Issues != nil {
		t.Fatalf("handler error = %+v", apiErr)
	}
	if !ofauth.IsAPIError(err, "resource_not_found") {
		t.Fatal("IsAPIError(resource_not_found) = false")
	}
}

func TestPagePagination(t *testing.T) {
	pages := map[string]any{
		"": map[string]any{
			"items": []any{map[string]any{"withUser": map[string]any{"id": 1}}, map[string]any{"withUser": map[string]any{"id": 2}}},
			"page":  map[string]any{"nextCursor": "c2", "hasMore": true},
		},
		"c2": map[string]any{
			"items": []any{map[string]any{"withUser": map[string]any{"id": 3}}},
			"page":  map[string]any{"nextCursor": nil, "hasMore": false},
		},
	}
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, 200, pages[r.URL.Query().Get("cursor")])
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn", BaseURL: ts.URL})

	count := 0
	for _, err := range client.Access.Chats.Iterate(context.Background(), ofauth.AccessChatsListParams{Limit: ofauth.Ptr(int64(2))}) {
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 3 {
		t.Fatalf("items = %d", count)
	}
	reqs := ts.Requests()
	if len(reqs) != 2 || reqs[1].Query["cursor"][0] != "c2" || reqs[1].Query["limit"][0] != "2" {
		t.Fatalf("requests = %+v", reqs)
	}

	// MaxItems stops early without fetching the second page.
	before := len(ts.Requests())
	count = 0
	for _, err := range client.Access.Chats.Iterate(context.Background(), ofauth.AccessChatsListParams{}, ofauth.MaxItems(2)) {
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 2 || len(ts.Requests())-before != 1 {
		t.Fatalf("MaxItems: items=%d requests=%d", count, len(ts.Requests())-before)
	}
}

func TestDataPaginationAndErrors(t *testing.T) {
	var calls atomic.Int32
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		calls.Add(1)
		switch r.URL.Query().Get("cursor") {
		case "":
			writeJSON(w, 200, map[string]any{"data": []any{map[string]any{"id": "conn_1"}}, "has_more": true, "next_cursor": "n2"})
		case "n2":
			writeJSON(w, 200, map[string]any{"data": []any{map[string]any{"id": "conn_2"}}, "has_more": true, "next_cursor": "n3"})
		default:
			writeJSON(w, 500, map[string]any{"error": "internal_error"})
		}
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), BaseURL: ts.URL})
	var ids []string
	var gotErr error
	for account, err := range client.LinkedAccounts.Iterate(context.Background(), ofauth.LinkedAccountsListParams{}) {
		if err != nil {
			gotErr = err
			break
		}
		ids = append(ids, account.ID)
	}
	if fmt.Sprint(ids) != "[conn_1 conn_2]" {
		t.Fatalf("ids = %v", ids)
	}
	if !ofauth.IsAPIError(gotErr, "internal_error") {
		t.Fatalf("err = %v", gotErr)
	}
}

func TestEmptyResponse(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(204)
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), BaseURL: ts.URL})
	if err := client.LinkedAccounts.Remove(context.Background(), ofauth.LinkedAccountsRemoveParams{ID: "conn_1"}); err != nil {
		t.Fatal(err)
	}
	if r := ts.Requests()[0]; r.Method != "DELETE" || r.Path != "/v3/linked-accounts/conn_1" {
		t.Fatalf("request = %s %s", r.Method, r.Path)
	}
}

func TestDecodeAny(t *testing.T) {
	type pair struct {
		A int `json:"a"`
	}
	got, err := ofauth.Decode[pair](map[string]any{"a": 3.0})
	if err != nil || got.A != 3 {
		t.Fatalf("Decode = %+v, %v", got, err)
	}
}
