package ofauthtest_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
	"github.com/ofauth-org/onlyfans-sdk-go/v4/ofauthtest"
)

func TestEveryEventTypeVerifiesAndRoutes(t *testing.T) {
	types := ofauthtest.EventTypes()
	all := append(append([]string{}, ofauth.LifecycleEventTypes...), ofauth.RealtimeEventTypes...)
	if len(types) != 17 || len(all) != 17 {
		t.Fatalf("event types = %d, constants = %d", len(types), len(all))
	}
	for _, eventType := range all {
		event, err := ofauthtest.CreateTestEvent(eventType, nil)
		if err != nil {
			t.Fatal(err)
		}
		var routed string
		router := ofauth.NewWebhookRouter(ofauthtest.WebhookSecret)
		router.On(eventType, func(ctx context.Context, e *ofauth.WebhookEvent) error {
			routed = e.Type
			return nil
		})
		got, err := ofauthtest.Deliver(context.Background(), router, ofauthtest.WebhookSecret, event)
		if err != nil {
			t.Fatalf("%s: %v", eventType, err)
		}
		if routed != eventType || got.Type != eventType || got.SchemaVersion != "1" || got.EventID == "" || len(got.Data) == 0 {
			t.Fatalf("%s: routed %q, event %+v", eventType, routed, got)
		}
	}
}

func TestCreateTestEventOverrides(t *testing.T) {
	a, _ := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationGranted, nil)
	b, _ := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationGranted, nil)
	if a["eventId"] == b["eventId"] {
		t.Fatal("eventId is not fresh")
	}
	event, err := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationGranted, map[string]any{
		"eventId":         "evt_fixed",
		"authorizationId": "authz_custom",
		"data":            map[string]any{"reason": "updated"},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := event["data"].(map[string]any)
	if event["eventId"] != "evt_fixed" || event["authorizationId"] != "authz_custom" || data["reason"] != "updated" || data["authorization_id"] == nil {
		t.Fatalf("event = %v", event)
	}
	if _, err := ofauthtest.CreateTestEvent("nope.nope", nil); err == nil {
		t.Fatal("unknown type accepted")
	}

	// Typed handlers decode the generated fixture.
	router := ofauth.NewWebhookRouter(ofauthtest.WebhookSecret)
	var got *ofauth.LifecycleAuthorizationGrantedEnvelope
	router.OnAuthorizationGranted(func(ctx context.Context, e *ofauth.LifecycleAuthorizationGrantedEnvelope) error {
		got = e
		return nil
	})
	if _, err := ofauthtest.Deliver(context.Background(), router, ofauthtest.WebhookSecret, event); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.AuthorizationID != "authz_custom" {
		t.Fatalf("typed event = %+v", got)
	}
}

func TestSignWebhook(t *testing.T) {
	at := time.Now().Add(-time.Minute)
	signed, err := ofauthtest.SignWebhook(`{"type":"x"}`, ofauthtest.WebhookSecret, ofauthtest.WithID("msg_1"), ofauthtest.WithTimestamp(at))
	if err != nil {
		t.Fatal(err)
	}
	if signed.Header.Get("webhook-id") != "msg_1" || string(signed.Body) != `{"type":"x"}` {
		t.Fatalf("signed = %+v", signed)
	}
	if _, err := ofauth.VerifyWebhook(signed.Body, signed.Header, ofauthtest.WebhookSecret, 0); err != nil {
		t.Fatal(err)
	}
	_, err = ofauth.VerifyWebhook(signed.Body, signed.Header, "whsec_"+"c29tZW90aGVyc2VjcmV0", 0)
	var verr *ofauth.WebhookVerificationError
	if !errors.As(err, &verr) || verr.Code != ofauth.WebhookSignatureMismatch {
		t.Fatalf("wrong secret err = %v", err)
	}
	if _, err := ofauthtest.SignWebhook("{}", "whsec_%%%"); err == nil {
		t.Fatal("invalid secret accepted")
	}

	// Through the http.Handler.
	event, _ := ofauthtest.CreateTestEvent(ofauth.EventRealtimeChatMessageReceived, nil)
	signed, _ = ofauthtest.SignWebhook(event, ofauthtest.WebhookSecret)
	router := ofauth.NewWebhookRouter(ofauthtest.WebhookSecret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, signed.Request("/webhooks/ofauth"))
	if rec.Code != http.StatusOK {
		t.Fatalf("ServeHTTP = %d %s", rec.Code, rec.Body)
	}
}
