// Command access calls Access operations: a single call, pagination, a write,
// retries and debug logging, and error handling with recovery actions.
//
//	OFAUTH_ACCESS_TOKEN=... OFAUTH_LINKED_ACCOUNT_ID=conn_... go run ./examples/access
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

func main() {
	ctx := context.Background()
	client := ofauth.NewClient(ofauth.Config{
		AccessToken:     ofauth.StaticToken(os.Getenv("OFAUTH_ACCESS_TOKEN")),
		LinkedAccountID: os.Getenv("OFAUTH_LINKED_ACCOUNT_ID"),
		// BaseURL: "https://api.staging.ofauth.com", // staging
		MaxRetries: ofauth.Ptr(3),    // default 2; ofauth.Ptr(0) disables retries
		Timeout:    30 * time.Second, // per attempt; default 60s
		Debug:      true,             // or OFAUTH_DEBUG=1: "[ofauth] GET /v3/access/profile -> 200 (123ms, req_...)"
	})

	// Linked accounts of this authorization (no linked account header needed).
	for account, err := range client.LinkedAccounts.Iterate(ctx, ofauth.LinkedAccountsListParams{}) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("linked account:", account.ID, account.Provider)
	}

	profile, err := client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{})
	if err != nil {
		handle(err)
		return
	}
	if profile.Username != nil {
		fmt.Println("profile:", *profile.Username)
	}

	// Iterate every chat, fetching pages as needed; stop after 50.
	for chat, err := range client.Access.Chats.Iterate(ctx, ofauth.AccessChatsListParams{Limit: ofauth.Ptr(int64(20))}, ofauth.MaxItems(50)) {
		if err != nil {
			handle(err)
			return
		}
		fmt.Println("chat with user", chat.User.ID)
	}

	// One page at a time.
	page, err := client.Access.Chats.List(ctx, ofauth.AccessChatsListParams{Limit: ofauth.Ptr(int64(10))})
	if err != nil {
		handle(err)
		return
	}
	fmt.Println("first page:", len(page.Items), "chats, more:", page.Page.HasMore)

	// Send a message (per-call linked account override shown).
	if len(page.Items) > 0 {
		_, err = client.Access.Chats.Messages.Send(ctx, ofauth.AccessChatsMessagesSendParams{
			UserID:          fmt.Sprint(page.Items[0].User.ID),
			Body:            ofauth.AccessChatsMessagesSendBody{Text: ofauth.Ptr("Thanks for subscribing!")},
			LinkedAccountID: os.Getenv("OFAUTH_LINKED_ACCOUNT_ID"),
		})
		if err != nil {
			handle(err)
		}
	}
}

// handle branches on the recovery action, not the HTTP status.
func handle(err error) {
	var apiErr *ofauth.APIError
	if !errors.As(err, &apiErr) {
		log.Fatal(err)
	}
	switch {
	case apiErr.NeedsReconnect():
		log.Printf("the owner must reconnect the account (%s)", apiErr.Code)
	case apiErr.NeedsReauthorization():
		// MissingScopes lists the scope to request again for missing_scope errors.
		log.Printf("send the user through Link again (%s, missing %v)", apiErr.Code, ofauth.MissingScopes(err))
	case apiErr.IsIntegrationProblem():
		log.Printf("fix the integration in the dashboard (%s)", apiErr.RecoveryAction)
	case apiErr.IsRetryable():
		log.Printf("retry in %s (already tried %d times)", apiErr.RetryAfter, apiErr.Attempts)
	default:
		log.Printf("API error %d %s on %s (request %s)", apiErr.StatusCode, apiErr.Code, apiErr.Operation, apiErr.RequestID)
	}
}
