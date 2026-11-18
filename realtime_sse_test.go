package ofauth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type parsed struct {
	messages []sseMessage
	retries  []int
	comments []string
}

func parse(t *testing.T, chunks []string, lastEventID string) parsed {
	t.Helper()
	var out parsed
	p := newSSEParser(lastEventID)
	p.onMessage = func(m sseMessage) { out.messages = append(out.messages, m) }
	p.onRetry = func(ms int) { out.retries = append(out.retries, ms) }
	p.onComment = func(text string) { out.comments = append(out.comments, text) }
	for _, chunk := range chunks {
		if err := p.push([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	p.end()
	return out
}

// split cuts s into chunks of n bytes.
func split(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

const sseStream = "\uFEFFretry: 3000\r\n" +
	": heartbeat\r\n" +
	"\r\n" +
	"id: 1\r\n" +
	"event: realtime.chat_message.received\r\n" +
	"data: {\"a\":1,\r\n" +
	"data:\"b\":2}\r\n" +
	"\r\n" +
	"data: no id, keeps 1\n\n" +
	"retry: 1.5\rretry: x\rretry: 250\r" +
	"id\r" + // an empty id resets the last event id
	"data\r\r" +
	"id: 9\x00\nevent: ignored-id\ndata: x\nunknown: field\n\n" +
	"event: resync\ndata: {}\n\n" +
	"data: unterminated" // discarded at end

func TestSSEParserInAnyChunking(t *testing.T) {
	want := []sseMessage{
		{event: "realtime.chat_message.received", data: "{\"a\":1,\n\"b\":2}", lastEventID: "1"},
		{event: "message", data: "no id, keeps 1", lastEventID: "1"},
		{event: "message", data: "", lastEventID: ""},
		{event: "ignored-id", data: "x", lastEventID: ""},
		{event: "resync", data: "{}", lastEventID: ""},
	}
	for _, size := range []int{1, 2, 3, 5, 7, 16, len(sseStream)} {
		got := parse(t, split(sseStream, size), "")
		if fmt.Sprint(got.messages) != fmt.Sprint(want) {
			t.Fatalf("chunks of %d: messages =\n%q\nwant\n%q", size, got.messages, want)
		}
		if fmt.Sprint(got.retries) != "[3000 250]" || fmt.Sprint(got.comments) != "[heartbeat]" {
			t.Fatalf("chunks of %d: retries = %v comments = %q", size, got.retries, got.comments)
		}
	}
}

func TestSSEParserSplitCRLFAndResume(t *testing.T) {
	// "\r" at the end of one chunk and "\n" at the start of the next is one line end.
	got := parse(t, []string{"data: a\r", "\n\r", "\ndata: b\n", "\n"}, "41")
	if len(got.messages) != 2 || got.messages[0].data != "a" || got.messages[1].data != "b" || got.messages[0].lastEventID != "41" {
		t.Fatalf("messages = %+v", got.messages)
	}
	// An event without data is not dispatched, but its id still counts.
	got = parse(t, []string{"id: 3\n\n", "data: c\n\n"}, "")
	if len(got.messages) != 1 || got.messages[0].lastEventID != "3" {
		t.Fatalf("messages = %+v", got.messages)
	}
	// A BOM only counts at the very start.
	got = parse(t, []string{"\uFEFF", "data: d\n\n\uFEFFdata: e\n\n"}, "")
	if len(got.messages) != 1 || got.messages[0].data != "d" {
		t.Fatalf("messages = %+v", got.messages)
	}
}

func TestSSEParserLineLimit(t *testing.T) {
	p := newSSEParser("")
	if err := p.push([]byte(strings.Repeat("x", realtimeMaxLine+1))); err == nil {
		t.Fatal("want an error for an overlong line")
	}
}

func TestParseRealtimeCloseReason(t *testing.T) {
	for data, want := range map[string]RealtimeCloseReason{
		`{"reason":"reauth"}`:      RealtimeCloseReauth,
		`{"reason":"replaced"}`:    RealtimeCloseReplaced,
		`{"reason":"unavailable"}`: RealtimeCloseUnavailable,
		`{"reason":"other"}`:       RealtimeCloseUnavailable,
		`not json`:                 RealtimeCloseUnavailable,
	} {
		if got := parseRealtimeCloseReason(data); got != want {
			t.Fatalf("%s: %s, want %s", data, got, want)
		}
	}
}

func TestEventIDWindow(t *testing.T) {
	w := newEventIDWindow(3)
	for _, id := range []string{"a", "b", "c"} {
		if !w.add(id) {
			t.Fatalf("%s: want new", id)
		}
	}
	if w.add("a") {
		t.Fatal("a: want a repeat")
	}
	w.add("d") // evicts a
	if !w.add("a") || w.add("c") {
		t.Fatal("window did not evict the oldest id")
	}
}

func TestRealtimeBackoff(t *testing.T) {
	c := newRealtimeConnection(realtimeConfig{MaxReconnectDelay: 10 * time.Second})
	c.randFloat = func() float64 { return 0 }
	var got []time.Duration
	for range 4 {
		got = append(got, c.backoffLocked(0))
	}
	if fmt.Sprint(got) != "[3s 6s 10s 10s]" {
		t.Fatalf("backoff = %v", got)
	}
	c.randFloat = func() float64 { return 1 }
	c.failures = 0
	c.retry = time.Second
	if d := c.backoffLocked(0); d != 1500*time.Millisecond {
		t.Fatalf("jittered = %s", d)
	}
	if d := c.backoffLocked(20 * time.Second); d != 20*time.Second {
		t.Fatalf("Retry-After = %s", d)
	}
}
