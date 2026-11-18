package ofauth_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

func TestCallerAuthorizationHeaderIsRejected(t *testing.T) {
	for _, name := range []string{"Authorization", "authorization", "AUTHORIZATION"} {
		calls := 0
		httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("unreachable")
		})}
		header := http.Header{}
		header[name] = []string{"Bearer caller-secret"} // bypass canonicalization, as a literal map would
		var requests []ofauth.RequestInfo
		client := ofauth.NewClient(ofauth.Config{
			AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: "http://api.test",
			HTTPClient: httpClient, Header: header, OnRequest: func(info ofauth.RequestInfo) { requests = append(requests, info) },
		})
		_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
		if !errors.Is(err, ofauth.ErrAuthorizationHeader) || strings.Contains(err.Error(), "caller-secret") || calls != 0 || len(requests) != 0 {
			t.Fatalf("%s: err = %v, calls = %d, hooks = %d", name, err, calls, len(requests))
		}
	}

	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), BaseURL: "http://api.test"})
	err := client.Do(context.Background(), &ofauth.Request{Method: http.MethodGet, Path: "/v3/x", Header: http.Header{"authorization": {"Bearer other"}}}, nil)
	if !errors.Is(err, ofauth.ErrAuthorizationHeader) {
		t.Fatalf("per-request: err = %v", err)
	}
}

func TestHeadersMergeCaseInsensitivelyAndAreRedacted(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	header := http.Header{}
	header["x-linked-account-id"] = []string{"conn_spoofed"}
	header["accept"] = []string{"text/plain"}
	header["cookie"] = []string{"session=c1"}
	header["X-API-Key"] = []string{"k1"}
	header["cf-access-client-secret"] = []string{"s1"}
	header["X-Upstream-Token"] = []string{"t1"}
	header["X-Trace"] = []string{"visible"}
	var requests []ofauth.RequestInfo
	client := ofauth.NewClient(ofauth.Config{
		AccessToken: ofauth.StaticToken("secret-token"), LinkedAccountID: "conn_1", BaseURL: srv.URL, Header: header,
		OnRequest: func(info ofauth.RequestInfo) { requests = append(requests, info) },
	})
	if _, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if v := got.Values("X-Linked-Account-Id"); len(v) != 1 || v[0] != "conn_1" {
		t.Fatalf("x-linked-account-id = %v", v)
	}
	if v := got.Values("Accept"); len(v) != 1 || v[0] != "application/json" {
		t.Fatalf("accept = %v", v)
	}
	if v := got.Values("Authorization"); len(v) != 1 || v[0] != "Bearer secret-token" {
		t.Fatalf("authorization = %v", v)
	}

	h := requests[0].Header
	want := map[string]string{
		"Authorization": "Bearer [REDACTED]", "Cookie": "[REDACTED]", "X-Api-Key": "[REDACTED]",
		"Cf-Access-Client-Secret": "[REDACTED]", "X-Upstream-Token": "[REDACTED]", "X-Trace": "visible",
	}
	for name, value := range want {
		if h.Get(name) != value {
			t.Fatalf("%s = %q, want %q (all: %v)", name, h.Get(name), value, h)
		}
	}
	dump := fmt.Sprint(requests)
	for _, secret := range []string{"secret-token", "c1", "k1", "s1", "t1"} {
		if strings.Contains(dump, secret) {
			t.Fatalf("hook saw %q: %s", secret, dump)
		}
	}
}

func TestRealtimeURLFor(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.ofauth.com":          "https://api.ofauth.com/v3/realtime/events",
		"https://api.staging.ofauth.com/": "https://api.staging.ofauth.com/v3/realtime/events",
		"HTTP://localhost:8787":           "HTTP://localhost:8787/v3/realtime/events",
	} {
		if got, err := ofauth.RealtimeURLForTest(in); err != nil || got != want {
			t.Fatalf("realtimeURLFor(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"ftp://example.com", "wss://api.ofauth.com", "api.ofauth.com", "https://"} {
		if _, err := ofauth.RealtimeURLForTest(bad); err == nil {
			t.Fatalf("%s: want an error", bad)
		}
	}
}

func TestClientRealtimeFollowsBaseURL(t *testing.T) {
	var mu sync.Mutex
	var path string
	srv, _ := sseServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		path = r.URL.Path
		mu.Unlock()
		openStream(w, "")
	})
	// The stream always goes to the BaseURL origin, never production.
	var requests []ofauth.RequestInfo
	client := ofauth.NewClient(ofauth.Config{
		AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: srv.URL,
		OnRequest: func(info ofauth.RequestInfo) { requests = append(requests, info) },
	})
	rt, err := client.Realtime(ofauth.RealtimeOptions{DisableReconnect: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-rt.Done()
	mu.Lock()
	defer mu.Unlock()
	wantURL := srv.URL + "/v3/realtime/events?linkedAccountId=conn_1"
	if path != "/v3/realtime/events" || len(requests) != 1 || requests[0].URL != wantURL {
		t.Fatalf("path = %q, requests = %+v", path, requests)
	}

	bad := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: "api.test"})
	if _, err := bad.Realtime(ofauth.RealtimeOptions{}); err == nil {
		t.Fatal("non-http BaseURL: want an error")
	}
}

func TestHooksAndErrorsGetSanitizedURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	var requests []ofauth.RequestInfo
	var responses []ofauth.ResponseInfo
	var gotQuery string
	client := ofauth.NewClient(ofauth.Config{
		AccessToken: ofauth.StaticToken("tok"), BaseURL: srv.URL,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotQuery = r.URL.RawQuery
			return http.DefaultTransport.RoundTrip(r)
		})},
		OnRequest:  func(info ofauth.RequestInfo) { requests = append(requests, info) },
		OnResponse: func(info ofauth.ResponseInfo) { responses = append(responses, info) },
	})
	signed := srv.URL + "/v3/access/uploads/u/parts/1?X-Amz-Signature=deadbeef&partNumber=1"
	if err := client.Do(context.Background(), &ofauth.Request{Method: http.MethodPut, Path: "/v3/access/uploads/u/parts/1", URL: signed, RawBody: []byte("x")}, nil); err != nil {
		t.Fatal(err)
	}
	want := srv.URL + "/v3/access/uploads/u/parts/1?X-Amz-Signature=REDACTED&partNumber=1"
	if gotQuery != "X-Amz-Signature=deadbeef&partNumber=1" || requests[0].URL != want || responses[0].URL != want {
		t.Fatalf("sent query = %q, hook URLs = %q, %q", gotQuery, requests[0].URL, responses[0].URL)
	}

	// A network failure: ConnectionError.URL, its message, and the hook's Err keep the signature out.
	boom := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	var failed []ofauth.ResponseInfo
	down := ofauth.NewClient(ofauth.Config{
		AccessToken: ofauth.StaticToken("tok"), BaseURL: "http://api.test", MaxRetries: ofauth.Ptr(0),
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, boom })},
		OnResponse: func(info ofauth.ResponseInfo) { failed = append(failed, info) },
		Timeout:    time.Second,
	})
	err := down.Do(context.Background(), &ofauth.Request{Method: http.MethodGet, Path: "/v3/x", URL: "http://api.test/v3/x?token=deadbeef&limit=5"}, nil)
	var connErr *ofauth.ConnectionError
	if !errors.As(err, &connErr) || connErr.URL != "http://api.test/v3/x?token=REDACTED&limit=5" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "deadbeef") || strings.Contains(failed[0].Err.Error(), "deadbeef") || strings.Contains(failed[0].URL, "deadbeef") {
		t.Fatalf("signed value leaked: %v / %+v", err, failed[0])
	}
}
