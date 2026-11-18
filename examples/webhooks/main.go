// Command webhooks receives OFAuth webhooks with WebhookRouter (an http.Handler).
//
//	OFAUTH_WEBHOOK_SECRET=whsec_... go run ./examples/webhooks
//
// main_test.go shows how to test the handlers with the ofauthtest package.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

func main() {
	http.Handle("/webhooks/ofauth", newRouter(os.Getenv("OFAUTH_WEBHOOK_SECRET")))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func newRouter(secret string) *ofauth.WebhookRouter {
	router := ofauth.NewWebhookRouter(secret)

	router.OnAuthorizationRevoked(func(ctx context.Context, e *ofauth.LifecycleAuthorizationRevokedEnvelope) error {
		log.Printf("authorization %s revoked: delete its tokens", e.AuthorizationID)
		return nil
	})
	router.OnLinkedAccountExpired(func(ctx context.Context, e *ofauth.LifecycleLinkedAccountExpiredEnvelope) error {
		log.Printf("linked account %s expired: ask the user to reconnect", e.LinkedAccountID)
		return nil
	})
	router.OnRealtimeChatMessageReceived(func(ctx context.Context, e *ofauth.RealtimeChatMessageReceivedEnvelope) error {
		log.Printf("message %d for %s", e.Data.ID, e.LinkedAccountID)
		return nil
	})
	// Everything else. Deduplicate on EventID and apply in Order per linked account.
	router.OnDefault(func(ctx context.Context, e *ofauth.WebhookEvent) error {
		log.Printf("event %s (%s)", e.Type, e.EventID)
		return nil
	})
	return router
}
