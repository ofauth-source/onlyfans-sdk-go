package ofauth_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

var webhookKey = []byte("super-secret-webhook-key-bytes!!")
var webhookSecret = "whsec_" + base64.StdEncoding.EncodeToString(webhookKey)

const revokedEvent = `{"eventId":"evt_1","type":"authorization.revoked","schemaVersion":"1","order":3,"occurredAt":"2026-01-01T00:00:00Z","environment":"live","integrationId":"int_1","externalOauthClientId":"ofext_live_x","authorizationId":"authz_1","linkedAccountId":null,"test":false,"data":{"authorization_id":"authz_1","reason":"user_revoked"}}`

func sign(id string, ts int64, body string) string {
	mac := hmac.New(sha256.New, webhookKey)
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "." + body))
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func webhookHeader(prefix string, id string, ts int64, signature string) http.Header {
	h := http.Header{}
	h.Set(prefix+"-id", id)
	h.Set(prefix+"-timestamp", strconv.FormatInt(ts, 10))
	h.Set(prefix+"-signature", signature)
	return h
}

func verificationCode(err error) string {
	var verr *ofauth.WebhookVerificationError
	if errors.As(err, &verr) {
		return verr.Code
	}
	return ""
}

func TestVerifyWebhook(t *testing.T) {
	now := time.Now().Unix()

	event, err := ofauth.VerifyWebhook([]byte(revokedEvent), webhookHeader("webhook", "msg_1", now, "v1,bogus "+sign("msg_1", now, revokedEvent)), webhookSecret, 0)
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != ofauth.EventAuthorizationRevoked || event.AuthorizationID != "authz_1" || event.LinkedAccountID != nil || event.Order != 3 || !event.IsLifecycle() {
		t.Fatalf("event = %+v", event)
	}

	// svix-* headers.
	if _, err := ofauth.VerifyWebhook([]byte(revokedEvent), webhookHeader("svix", "msg_1", now, sign("msg_1", now, revokedEvent)), webhookSecret, 0); err != nil {
		t.Fatalf("svix headers: %v", err)
	}

	// Bad signature.
	_, err = ofauth.VerifyWebhook([]byte(revokedEvent), webhookHeader("webhook", "msg_1", now, sign("msg_2", now, revokedEvent)), webhookSecret, 0)
	if verificationCode(err) != ofauth.WebhookSignatureMismatch {
		t.Fatalf("bad signature err = %v", err)
	}

	// Old timestamp.
	old := now - 600
	_, err = ofauth.VerifyWebhook([]byte(revokedEvent), webhookHeader("webhook", "msg_1", old, sign("msg_1", old, revokedEvent)), webhookSecret, 0)
	if verificationCode(err) != ofauth.WebhookTimestampOutOfTolerance {
		t.Fatalf("old timestamp err = %v", err)
	}
	// ...accepted with a wider tolerance.
	if _, err := ofauth.VerifyWebhook([]byte(revokedEvent), webhookHeader("webhook", "msg_1", old, sign("msg_1", old, revokedEvent)), webhookSecret, time.Hour); err != nil {
		t.Fatalf("wide tolerance: %v", err)
	}

	// Missing headers, bad timestamp, no v1 signatures, invalid JSON.
	if code := verificationCode(func() error {
		_, err := ofauth.VerifyWebhook([]byte(revokedEvent), http.Header{}, webhookSecret, 0)
		return err
	}()); code != ofauth.WebhookMissingHeaders {
		t.Fatalf("missing headers code = %q", code)
	}
	h := webhookHeader("webhook", "msg_1", now, "v1,x")
	h.Set("webhook-timestamp", "soon")
	if _, err := ofauth.VerifyWebhook([]byte(revokedEvent), h, webhookSecret, 0); verificationCode(err) != ofauth.WebhookInvalidTimestamp {
		t.Fatalf("invalid timestamp err = %v", err)
	}
	if _, err := ofauth.VerifyWebhook([]byte(revokedEvent), webhookHeader("webhook", "msg_1", now, "v2,abc"), webhookSecret, 0); verificationCode(err) != ofauth.WebhookNoValidSignatures {
		t.Fatalf("no v1 err = %v", err)
	}
	if _, err := ofauth.VerifyWebhook([]byte("nope"), webhookHeader("webhook", "msg_1", now, sign("msg_1", now, "nope")), webhookSecret, 0); verificationCode(err) != ofauth.WebhookInvalidJSON {
		t.Fatalf("invalid json err = %v", err)
	}
}

func TestWebhookRouterHTTPHandler(t *testing.T) {
	var revoked *ofauth.LifecycleAuthorizationRevokedEnvelope
	var defaults []string
	router := ofauth.NewWebhookRouter(webhookSecret)
	router.OnAuthorizationRevoked(func(ctx context.Context, event *ofauth.LifecycleAuthorizationRevokedEnvelope) error {
		revoked = event
		return nil
	})
	router.OnDefault(func(ctx context.Context, event *ofauth.WebhookEvent) error {
		defaults = append(defaults, event.Type)
		return nil
	})

	post := func(body string, header http.Header) int {
		req := httptest.NewRequest(http.MethodPost, "/webhooks", bytes.NewBufferString(body))
		for k, v := range header {
			req.Header[k] = v
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	now := time.Now().Unix()
	if code := post(revokedEvent, webhookHeader("webhook", "m1", now, sign("m1", now, revokedEvent))); code != 200 {
		t.Fatalf("status = %d", code)
	}
	if revoked == nil || revoked.AuthorizationID != "authz_1" || revoked.Data.AuthorizationID != "authz_1" {
		t.Fatalf("revoked = %+v", revoked)
	}

	other := `{"eventId":"evt_2","type":"realtime.toasts.received","schemaVersion":"1","order":1,"linkedAccountId":"conn_1","data":{}}`
	if code := post(other, webhookHeader("webhook", "m2", now, sign("m2", now, other))); code != 200 || len(defaults) != 1 {
		t.Fatalf("default handler: status %d, defaults %v", code, defaults)
	}

	if code := post(revokedEvent, webhookHeader("webhook", "m1", now, sign("m1", now, "tampered"))); code != 401 {
		t.Fatalf("bad signature status = %d", code)
	}

	router.OnAuthorizationRevoked(func(ctx context.Context, event *ofauth.LifecycleAuthorizationRevokedEnvelope) error {
		return errors.New("db down")
	})
	if code := post(revokedEvent, webhookHeader("webhook", "m1", now, sign("m1", now, revokedEvent))); code != 500 {
		t.Fatalf("handler error status = %d", code)
	}
}
