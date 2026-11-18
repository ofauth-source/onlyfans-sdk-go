package ofauth

import (
	"context"
	"time"
)

// SetRetryClock replaces the client's retry sleep and backoff jitter, so
// tests never wait for real.
func SetRetryClock(c *Client, sleep func(ctx context.Context, d time.Duration) error, jitter func() float64) {
	c.rt.sleep = sleep
	c.rt.jitter = jitter
}

// RealtimeURLForTest exposes the unexported Realtime URL derivation.
var RealtimeURLForTest = realtimeURLFor
