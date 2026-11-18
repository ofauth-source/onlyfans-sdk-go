// Command realtime streams Realtime events for one linked account.
//
//	OFAUTH_ACCESS_TOKEN=... OFAUTH_LINKED_ACCOUNT_ID=conn_... go run ./examples/realtime
package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := ofauth.NewClient(ofauth.Config{
		AccessToken:     ofauth.StaticToken(os.Getenv("OFAUTH_ACCESS_TOKEN")),
		LinkedAccountID: os.Getenv("OFAUTH_LINKED_ACCOUNT_ID"),
	})
	rt, err := client.Realtime(ofauth.RealtimeOptions{})
	if err != nil {
		log.Fatal(err)
	}

	rt.OnRealtimeChatMessageReceived(func(e *ofauth.RealtimeEvent, d *ofauth.RealtimeChatMessageReceivedData) {
		log.Printf("new message %d", d.ID)
	})
	rt.OnEvent(func(e *ofauth.RealtimeEvent) { log.Printf("%s #%d", e.Type, e.Order) })
	rt.OnResync(func() { log.Print("events were missed: refetch state through the REST API") })
	rt.OnClose(func(info ofauth.RealtimeCloseInfo) {
		log.Printf("closed: %s (status %d, reconnect: %v in %s)", info.Reason, info.Status, info.WillReconnect, info.RetryIn)
	})
	rt.OnError(func(err error) { log.Printf("realtime error: %v", err) })

	// A failed first attempt returns the error, e.g. a 403 *APIError when
	// Realtime is not enabled for this integration.
	if err := rt.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	<-rt.Done()
	if err := rt.Err(); err != nil {
		log.Printf("stopped: %v", err)
	}
	// Pass this as RealtimeOptions.LastEventID to resume after a restart.
	log.Printf("last event id: %s", rt.LastEventID())
}
