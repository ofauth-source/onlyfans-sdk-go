// Package ofauthtest helps test OFAuth webhook handlers: it builds valid
// event envelopes for every event type (from the OpenAPI examples) and signs
// them like OFAuth does.
//
//	router := ofauth.NewWebhookRouter(ofauthtest.WebhookSecret)
//	router.OnAuthorizationRevoked(handleRevoked)
//
//	event, _ := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationRevoked, map[string]any{
//		"authorizationId": "authz_123",
//	})
//	_, err := ofauthtest.Deliver(ctx, router, ofauthtest.WebhookSecret, event)
package ofauthtest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

// WebhookSecret is a valid whsec_ signing secret for tests.
const WebhookSecret = "whsec_b2ZhdXRoLXRlc3Qtd2ViaG9vay1zZWNyZXQtMzJieXRlcw=="

// EventTypes returns every event type with a fixture, sorted.
func EventTypes() []string {
	types := make([]string, 0, len(fixtures))
	for t := range fixtures {
		types = append(types, t)
	}
	slices.Sort(types)
	return types
}

// CreateTestEvent returns a valid envelope for eventType (one of the
// ofauth.Event* constants), built from the spec's example, with overrides
// deep-merged into it (nested objects are merged, other values replaced). It
// gets a fresh eventId unless overrides sets one.
func CreateTestEvent(eventType string, overrides map[string]any) (map[string]any, error) {
	fixture, ok := fixtures[eventType]
	if !ok {
		return nil, fmt.Errorf("ofauthtest: unknown event type %q", eventType)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(fixture), &event); err != nil {
		return nil, fmt.Errorf("ofauthtest: fixture %s: %w", eventType, err)
	}
	event["eventId"] = "evt_test_" + randomHex(12)
	merge(event, overrides)
	return event, nil
}

func merge(dst, src map[string]any) {
	for key, value := range src {
		if srcMap, ok := value.(map[string]any); ok {
			if dstMap, ok := dst[key].(map[string]any); ok {
				merge(dstMap, srcMap)
				continue
			}
		}
		dst[key] = value
	}
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// SignOption configures SignWebhook.
type SignOption func(*signOptions)

type signOptions struct {
	id        string
	timestamp time.Time
}

// WithID sets the webhook-id header. Defaults to a random msg_ id.
func WithID(id string) SignOption {
	return func(o *signOptions) { o.id = id }
}

// WithTimestamp sets the webhook-timestamp. Defaults to now.
func WithTimestamp(t time.Time) SignOption {
	return func(o *signOptions) { o.timestamp = t }
}

// SignedWebhook is a signed delivery.
type SignedWebhook struct {
	// Header has webhook-id, webhook-timestamp, webhook-signature ("v1,<sig>"),
	// and Content-Type.
	Header http.Header
	// Body is the exact signed body.
	Body []byte
}

// Request returns a POST request to target carrying the delivery, for
// handler.ServeHTTP with an httptest.ResponseRecorder.
func (s *SignedWebhook) Request(target string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(s.Body))
	for key, values := range s.Header {
		req.Header[key] = append([]string(nil), values...)
	}
	return req
}

// SignWebhook signs payload with a whsec_ secret like OFAuth does. payload is
// a []byte or string sent as-is, or any other value encoded as JSON (e.g. the
// result of CreateTestEvent).
func SignWebhook(payload any, secret string, opts ...SignOption) (*SignedWebhook, error) {
	o := signOptions{id: "msg_" + randomHex(12), timestamp: time.Now()}
	for _, opt := range opts {
		opt(&o)
	}
	var body []byte
	switch v := payload.(type) {
	case []byte:
		body = v
	case string:
		body = []byte(v)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("ofauthtest: encode payload: %w", err)
		}
		body = encoded
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return nil, fmt.Errorf("ofauthtest: secret is not valid base64: %w", err)
	}
	timestamp := strconv.FormatInt(o.timestamp.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(o.id + "." + timestamp + "."))
	mac.Write(body)
	header := http.Header{}
	header.Set("webhook-id", o.id)
	header.Set("webhook-timestamp", timestamp)
	header.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	header.Set("Content-Type", "application/json")
	return &SignedWebhook{Header: header, Body: body}, nil
}

// Deliver signs payload (see SignWebhook) and runs it through the router,
// returning the verified event and the handler's error.
func Deliver(ctx context.Context, router *ofauth.WebhookRouter, secret string, payload any, opts ...SignOption) (*ofauth.WebhookEvent, error) {
	signed, err := SignWebhook(payload, secret, opts...)
	if err != nil {
		return nil, err
	}
	return router.Handle(ctx, signed.Body, signed.Header)
}
