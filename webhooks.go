package ofauth

// Webhook verification and routing.
//
// Deliveries follow Standard Webhooks (https://www.standardwebhooks.com): the
// webhook-id, webhook-timestamp, and webhook-signature headers, with an
// HMAC-SHA256 signature over "{id}.{timestamp}.{body}" keyed by the
// destination's whsec_ secret. svix-* headers are accepted too.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultWebhookTolerance is the maximum age of a delivery.
const DefaultWebhookTolerance = 5 * time.Minute

// Webhook verification error codes.
const (
	WebhookMissingHeaders          = "MISSING_HEADERS"
	WebhookInvalidTimestamp        = "INVALID_TIMESTAMP"
	WebhookTimestampOutOfTolerance = "TIMESTAMP_OUT_OF_TOLERANCE"
	WebhookNoValidSignatures       = "NO_VALID_SIGNATURES"
	WebhookSignatureMismatch       = "SIGNATURE_MISMATCH"
	WebhookInvalidJSON             = "INVALID_JSON"
)

const webhookMaxBodyBytes = 5 << 20

// WebhookVerificationError means the delivery failed verification. Respond
// with 400 or 401 and do not process it.
type WebhookVerificationError struct {
	// Code is one of the Webhook* error code constants.
	Code    string
	Message string
}

// Error implements error.
func (e *WebhookVerificationError) Error() string {
	return "ofauth: webhook verification failed: " + e.Code + ": " + e.Message
}

// WebhookHeaders are the signature headers of one delivery.
type WebhookHeaders struct {
	ID        string
	Timestamp string
	Signature string
}

// ExtractWebhookHeaders reads the webhook-* (or svix-*) headers.
func ExtractWebhookHeaders(header http.Header) (WebhookHeaders, error) {
	pick := func(primary, fallback string) string {
		if v := header.Get(primary); v != "" {
			return v
		}
		return header.Get(fallback)
	}
	h := WebhookHeaders{
		ID:        pick("webhook-id", "svix-id"),
		Timestamp: pick("webhook-timestamp", "svix-timestamp"),
		Signature: pick("webhook-signature", "svix-signature"),
	}
	if h.ID == "" || h.Timestamp == "" || h.Signature == "" {
		return h, &WebhookVerificationError{Code: WebhookMissingHeaders, Message: "missing webhook-id, webhook-timestamp, or webhook-signature header"}
	}
	return h, nil
}

// WebhookEvent is a delivery's envelope with its data kept raw. Every event
// (lifecycle and Realtime) has these fields; Data depends on Type. Use the
// typed WebhookRouter.On* methods or DecodeData for the per-type structs.
type WebhookEvent struct {
	EventID       string `json:"eventId"`
	Type          string `json:"type"`
	SchemaVersion string `json:"schemaVersion"`
	// Order increases per linked account. Apply events in order; deduplicate on EventID.
	Order      int64  `json:"order"`
	OccurredAt string `json:"occurredAt"`
	// Environment is sandbox, test, or live.
	Environment           string `json:"environment"`
	IntegrationID         string `json:"integrationId"`
	ExternalOAuthClientID string `json:"externalOauthClientId"`
	AuthorizationID       string `json:"authorizationId"`
	// LinkedAccountID is nil for authorization.* events.
	LinkedAccountID *string         `json:"linkedAccountId"`
	Test            bool            `json:"test"`
	Data            json.RawMessage `json:"data"`
	// Raw is the whole delivery body.
	Raw json.RawMessage `json:"-"`
}

// DecodeData decodes the event's data into v (e.g. *RealtimeChatMessageReceivedData).
func (e *WebhookEvent) DecodeData(v any) error {
	return json.Unmarshal(e.Data, v)
}

// IsLifecycle reports whether this is an authorization.* or linked_account.* event.
func (e *WebhookEvent) IsLifecycle() bool {
	return strings.HasPrefix(e.Type, "authorization.") || strings.HasPrefix(e.Type, "linked_account.")
}

// VerifyWebhookSignature verifies a delivery's signature against the raw body.
// tolerance <= 0 uses DefaultWebhookTolerance.
func VerifyWebhookSignature(payload []byte, headers WebhookHeaders, secret string, tolerance time.Duration) error {
	return verifyAt(payload, headers, secret, tolerance, time.Now())
}

func verifyAt(payload []byte, headers WebhookHeaders, secret string, tolerance time.Duration, now time.Time) error {
	if tolerance <= 0 {
		tolerance = DefaultWebhookTolerance
	}
	ts, err := strconv.ParseInt(headers.Timestamp, 10, 64)
	if err != nil {
		return &WebhookVerificationError{Code: WebhookInvalidTimestamp, Message: "invalid webhook-timestamp"}
	}
	if math.Abs(float64(now.Unix()-ts)) > tolerance.Seconds() {
		return &WebhookVerificationError{Code: WebhookTimestampOutOfTolerance, Message: "webhook timestamp is outside the tolerance"}
	}

	var signatures []string
	for _, entry := range strings.Split(headers.Signature, " ") {
		version, value, ok := strings.Cut(entry, ",")
		if ok && version == "v1" && value != "" {
			signatures = append(signatures, value)
		}
	}
	if len(signatures) == 0 {
		return &WebhookVerificationError{Code: WebhookNoValidSignatures, Message: "no v1 signature in webhook-signature"}
	}

	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return &WebhookVerificationError{Code: WebhookSignatureMismatch, Message: "webhook secret is not valid base64"}
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(headers.ID + "." + headers.Timestamp + "."))
	mac.Write(payload)
	expected := []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	for _, signature := range signatures {
		if hmac.Equal([]byte(signature), expected) {
			return nil
		}
	}
	return &WebhookVerificationError{Code: WebhookSignatureMismatch, Message: "webhook signature does not match"}
}

// VerifyWebhook verifies a delivery and parses its envelope. Pass the raw
// body exactly as received. tolerance <= 0 uses DefaultWebhookTolerance.
//
//	body, _ := io.ReadAll(r.Body)
//	event, err := ofauth.VerifyWebhook(body, r.Header, os.Getenv("OFAUTH_WEBHOOK_SECRET"), 0)
func VerifyWebhook(payload []byte, header http.Header, secret string, tolerance time.Duration) (*WebhookEvent, error) {
	headers, err := ExtractWebhookHeaders(header)
	if err != nil {
		return nil, err
	}
	if err := VerifyWebhookSignature(payload, headers, secret, tolerance); err != nil {
		return nil, err
	}
	return parseWebhookEvent(payload)
}

func parseWebhookEvent(payload []byte) (*WebhookEvent, error) {
	var event WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, &WebhookVerificationError{Code: WebhookInvalidJSON, Message: "webhook body is not valid JSON"}
	}
	event.Raw = append(json.RawMessage(nil), payload...)
	return &event, nil
}

// ============================================================================
// Router
// ============================================================================

// WebhookHandler handles one verified event.
type WebhookHandler func(ctx context.Context, event *WebhookEvent) error

// WebhookRouter verifies deliveries and dispatches them by Type. It
// implements http.Handler: 200 on success, 401 {"error": code} on failed
// verification, 500 {"error": "handler_failed"} when a handler fails.
//
// Deduplicate on EventID, and apply events per LinkedAccountID in Order:
// retried deliveries can arrive out of order.
//
//	router := ofauth.NewWebhookRouter(os.Getenv("OFAUTH_WEBHOOK_SECRET"))
//	router.OnAuthorizationRevoked(func(ctx context.Context, e *ofauth.LifecycleAuthorizationRevokedEnvelope) error {
//		return deleteTokens(e.AuthorizationID)
//	})
//	http.Handle("/webhooks/ofauth", router)
type WebhookRouter struct {
	mu             sync.RWMutex
	secret         string
	tolerance      time.Duration
	handlers       map[string]WebhookHandler
	defaultHandler WebhookHandler
}

// NewWebhookRouter returns a router for the destination's whsec_ signing secret.
func NewWebhookRouter(secret string) *WebhookRouter {
	return &WebhookRouter{secret: secret, handlers: map[string]WebhookHandler{}}
}

// On handles one event type (see the Event* constants).
func (r *WebhookRouter) On(eventType string, handler WebhookHandler) *WebhookRouter {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[eventType] = handler
	return r
}

// OnDefault handles events without a specific handler.
func (r *WebhookRouter) OnDefault(handler WebhookHandler) *WebhookRouter {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultHandler = handler
	return r
}

// SetSecret rotates the signing secret.
func (r *WebhookRouter) SetSecret(secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secret = secret
}

// SetTolerance sets the maximum delivery age (default DefaultWebhookTolerance).
func (r *WebhookRouter) SetTolerance(tolerance time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tolerance = tolerance
}

// Handle verifies and dispatches a raw delivery and returns the event.
func (r *WebhookRouter) Handle(ctx context.Context, payload []byte, header http.Header) (*WebhookEvent, error) {
	r.mu.RLock()
	secret, tolerance := r.secret, r.tolerance
	r.mu.RUnlock()
	event, err := VerifyWebhook(payload, header, secret, tolerance)
	if err != nil {
		return nil, err
	}
	return event, r.Dispatch(ctx, event)
}

// Dispatch runs the handler for an already verified event.
func (r *WebhookRouter) Dispatch(ctx context.Context, event *WebhookEvent) error {
	r.mu.RLock()
	handler, ok := r.handlers[event.Type]
	if !ok {
		handler = r.defaultHandler
	}
	r.mu.RUnlock()
	if handler == nil {
		return nil
	}
	return handler(ctx, event)
}

// ServeHTTP verifies and dispatches a delivery.
func (r *WebhookRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeWebhookJSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, webhookMaxBodyBytes))
	if err != nil {
		writeWebhookJSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if _, err := r.Handle(req.Context(), body, req.Header); err != nil {
		var verr *WebhookVerificationError
		if errors.As(err, &verr) {
			writeWebhookJSON(w, http.StatusUnauthorized, verr.Code)
			return
		}
		writeWebhookJSON(w, http.StatusInternalServerError, "handler_failed")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func writeWebhookJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
