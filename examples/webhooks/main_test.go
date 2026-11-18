package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
	"github.com/ofauth-org/onlyfans-sdk-go/v4/ofauthtest"
)

func TestRevokedWebhook(t *testing.T) {
	router := newRouter(ofauthtest.WebhookSecret)
	event, err := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationRevoked, map[string]any{"authorizationId": "authz_123"})
	if err != nil {
		t.Fatal(err)
	}

	// One call: sign and dispatch.
	if _, err := ofauthtest.Deliver(context.Background(), router, ofauthtest.WebhookSecret, event); err != nil {
		t.Fatal(err)
	}

	// Or through the http.Handler.
	signed, err := ofauthtest.SignWebhook(event, ofauthtest.WebhookSecret)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, signed.Request("/webhooks/ofauth"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
