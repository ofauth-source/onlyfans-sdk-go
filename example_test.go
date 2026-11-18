package ofauth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
	"github.com/ofauth-org/onlyfans-sdk-go/v4/ofauthtest"
)

// fakeAPI stands in for api.ofauth.com in the examples.
func fakeAPI() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = r.ParseForm()
		switch {
		case r.URL.Path == "/v3/link/token":
			io.WriteString(w, `{"access_token":"at_1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt_1",
				"scope":"profile:read","authorization_id":"authz_1",
				"linked_accounts":{"data":[{"id":"conn_1","provider":"onlyfans"}],"has_more":false,"next_cursor":null}}`)
		case r.URL.Path == "/v3/access/profile" && r.Header.Get(ofauth.LinkedAccountHeader) == "conn_gone":
			w.Header().Set("X-Request-Id", "req_123")
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error":"linked_account_reconnect_required","recovery":{"action":"reconnect_linked_account"}}`)
		case r.URL.Path == "/v3/access/profile":
			io.WriteString(w, `{"id":1,"username":"creator"}`)
		case r.URL.Path == "/v3/linked-accounts" && r.Form.Get("cursor") == "":
			io.WriteString(w, `{"data":[{"id":"conn_1"},{"id":"conn_2"}],"has_more":true,"next_cursor":"c2"}`)
		case r.URL.Path == "/v3/linked-accounts":
			io.WriteString(w, `{"data":[{"id":"conn_3"}],"has_more":false,"next_cursor":null}`)
		case r.URL.Path == "/v3/realtime/events":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "retry: 3000\n\n: heartbeat\n\nid: 1\nevent: realtime.chat_message.received\n"+
				`data: {"eventId":"evt_1","type":"realtime.chat_message.received","order":1,"linkedAccountId":"conn_1","data":{"id":5,"withUserId":7}}`+
				"\n\nevent: closed\ndata: {\"reason\":\"replaced\"}\n\n")
		case r.URL.Path == "/v3/realtime" && r.Method == http.MethodPost:
			io.WriteString(w, `{"url":"https://api.ofauth.com/v3/realtime/events?linkedAccountId=conn_1&streamToken=rst_1","expiresAt":"2026-01-01T00:10:00Z"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"not_found"}`)
		}
	}))
}

func ExampleNewClient() {
	api := fakeAPI()
	defer api.Close()

	client := ofauth.NewClient(ofauth.Config{
		AccessToken:     ofauth.StaticToken("at_1"),
		LinkedAccountID: "conn_1",
		BaseURL:         api.URL, // omit in production
	})
	profile, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(*profile.Username)
	// Output: creator
}

func ExampleClient_Realtime() {
	api := fakeAPI()
	defer api.Close()

	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("at_1"), LinkedAccountID: "conn_1", BaseURL: api.URL})
	rt, err := client.Realtime(ofauth.RealtimeOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	rt.OnRealtimeChatMessageReceived(func(e *ofauth.RealtimeEvent, d *ofauth.RealtimeChatMessageReceivedData) {
		fmt.Println("message", d.ID, "from", *d.WithUserID)
	})
	rt.OnResync(func() { fmt.Println("refetch") })
	rt.OnClose(func(info ofauth.RealtimeCloseInfo) { fmt.Println("closed:", info.Reason, info.WillReconnect) })
	if err := rt.Connect(context.Background()); err != nil {
		fmt.Println(err)
		return
	}
	<-rt.Done()
	fmt.Println("resume after", rt.LastEventID())
	// Output:
	// message 5 from 7
	// closed: replaced false
	// resume after 1
}

func ExampleClient_CreateRealtimeStreamURL() {
	api := fakeAPI()
	defer api.Close()

	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("at_1"), LinkedAccountID: "conn_1", BaseURL: api.URL})
	// Send only stream.URL to the browser; the access token stays on the server.
	stream, err := client.CreateRealtimeStreamURL(context.Background(), ofauth.CreateRealtimeStreamURLParams{})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(stream.ExpiresAt)
	// Output: 2026-01-01T00:10:00Z
}

func ExampleLinkedAccountsService_Iterate() {
	api := fakeAPI()
	defer api.Close()
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("at_1"), BaseURL: api.URL})

	for account, err := range client.LinkedAccounts.Iterate(context.Background(), ofauth.LinkedAccountsListParams{}) {
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(account.ID)
	}
	// Output:
	// conn_1
	// conn_2
	// conn_3
}

func ExampleAPIError() {
	api := fakeAPI()
	defer api.Close()
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("at_1"), LinkedAccountID: "conn_gone", BaseURL: api.URL})

	_, err := client.Access.Profile.Get(context.Background(), ofauth.AccessProfileGetParams{})
	var apiErr *ofauth.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.NeedsReconnect():
			fmt.Println("ask the creator to reconnect", apiErr.RequestID)
		case apiErr.NeedsReauthorization():
			fmt.Println("send the user through authorization again")
		case apiErr.IsRetryable():
			fmt.Println("try again later")
		}
	}
	// Output: ask the creator to reconnect req_123
}

func ExampleScopesFor() {
	scopes, err := ofauth.ScopesFor("access.chats.messages.send", "access.profile.get", "linkedAccounts.list")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(scopes)
	// Output: [messages:write profile:read]
}

func ExampleWebhookRouter() {
	router := ofauth.NewWebhookRouter(ofauthtest.WebhookSecret)
	router.OnAuthorizationRevoked(func(ctx context.Context, e *ofauth.LifecycleAuthorizationRevokedEnvelope) error {
		fmt.Println("revoked", e.AuthorizationID)
		return nil
	})

	// In tests, sign a generated event and run it through the router.
	event, _ := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationRevoked, map[string]any{"authorizationId": "authz_123"})
	if _, err := ofauthtest.Deliver(context.Background(), router, ofauthtest.WebhookSecret, event); err != nil {
		fmt.Println(err)
	}
	// Output: revoked authz_123
}
