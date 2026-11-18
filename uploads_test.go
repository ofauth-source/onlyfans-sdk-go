package ofauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

func TestMD5Hex(t *testing.T) {
	cases := map[string]string{
		"": "d41d8cd98f00b204e9800998ecf8427e",
		"The quick brown fox jumps over the lazy dog": "9e107d9d372bb6826bd81d3542a419d6",
	}
	for in, want := range cases {
		if got := ofauth.MD5Hex([]byte(in)); got != want {
			t.Errorf("MD5Hex(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestUploadMediaFlow(t *testing.T) {
	data := []byte("0123456789")
	var ts *testServer
	ts = newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		switch r.URL.Path {
		case "/v3/access/uploads/start":
			writeJSON(w, 200, map[string]any{
				"status": "needs_upload", "uploadId": "up_1", "uploadType": "multipart", "totalParts": 2, "partSize": 6,
				"expiresAt": "2030-01-01T00:00:00Z",
				"parts": []any{
					map[string]any{"partNumber": 1, "uploadUrl": ts.URL + "/v3/access/uploads/up_1/parts/1", "byteRange": map[string]any{"start": 0, "end": 5}},
					map[string]any{"partNumber": 2, "uploadUrl": ts.URL + "/v3/access/uploads/up_1/parts/2", "byteRange": map[string]any{"start": 6, "end": 9}},
				},
			})
		case "/v3/access/uploads/finalize":
			writeJSON(w, 200, map[string]any{
				"uploadIds": []string{"up_1"}, "listId": 9,
				"uploads": []any{map[string]any{"uploadId": "up_1", "mediaId": 4242, "media": map[string]any{"id": 4242, "type": "photo"}}},
			})
		default:
			w.WriteHeader(200)
		}
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: ts.URL})

	var progress [][2]int64
	result, err := client.UploadMedia(context.Background(), data, ofauth.UploadMediaOptions{
		Filename:    "upload.png",
		ContentType: "image/png",
		VaultUpload: &ofauth.VaultUpload{UserID: "u1", ListID: ofauth.Ptr(int64(9))},
		OnProgress:  func(uploaded, total int64) { progress = append(progress, [2]int64{uploaded, total}) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ofauth.UploadStatusUploaded || result.UploadID != "up_1" || result.Finalize == nil || result.Finalize.UploadIDs[0] != "up_1" {
		t.Fatalf("result = %+v", result)
	}
	if f := result.Finalize; len(f.Uploads) != 1 || f.Uploads[0].Media.ID != 4242 || f.ListID == nil || *f.ListID != 9 ||
		len(result.VaultMediaIDs) != 1 || result.VaultMediaIDs[0] != 4242 || result.Media != nil {
		t.Fatalf("finalize = %+v, vault media = %v", result.Finalize, result.VaultMediaIDs)
	}

	reqs := ts.Requests()
	if len(reqs) != 4 {
		t.Fatalf("requests = %d", len(reqs))
	}
	var start map[string]any
	_ = json.Unmarshal(reqs[0].Body, &start)
	if start["etag"] != ofauth.MD5Hex(data) || start["size"] != float64(10) || start["contentType"] != "image/png" {
		t.Fatalf("start body = %s", reqs[0].Body)
	}
	if reqs[1].Method != "PUT" || string(reqs[1].Body) != "012345" || reqs[2].Path != "/v3/access/uploads/up_1/parts/2" || string(reqs[2].Body) != "6789" {
		t.Fatalf("parts = %q %q", reqs[1].Body, reqs[2].Body)
	}
	for _, r := range reqs[1:3] {
		if r.Header.Get("Content-Type") != "image/png" || r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("x-linked-account-id") != "conn_1" {
			t.Fatalf("part headers = %v", r.Header)
		}
	}
	if string(reqs[3].Body) != `{"uploadIds":["up_1"],"vaultUpload":{"userId":"u1","listId":9}}` {
		t.Fatalf("finalize body = %s", reqs[3].Body)
	}
	if len(progress) != 2 || progress[1] != [2]int64{10, 10} {
		t.Fatalf("progress = %v", progress)
	}
}

func TestUploadMediaAlreadyExists(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, 200, map[string]any{"status": "already_exists", "media": map[string]any{"id": 777, "type": "photo"}})
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: ts.URL})
	result, err := client.UploadMedia(context.Background(), []byte("x"), ofauth.UploadMediaOptions{Filename: "upload.png", ContentType: "image/jpeg", ETag: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ofauth.UploadStatusAlreadyExists || result.MediaID != 777 || result.Media == nil || result.Media.ID != 777 ||
		result.Media.Type != "photo" || result.VaultMediaIDs != nil {
		t.Fatalf("result = %+v", result)
	}
	if n := len(ts.Requests()); n != 1 {
		t.Fatalf("requests = %d", n)
	}
	var start map[string]any
	_ = json.Unmarshal(ts.Requests()[0].Body, &start)
	if start["etag"] != "custom" {
		t.Fatalf("etag = %v", start["etag"])
	}
}

func TestUploadMediaVaultMediaIDsFallback(t *testing.T) {
	var ts *testServer
	ts = newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		switch r.URL.Path {
		case "/v3/access/uploads/start":
			writeJSON(w, 200, map[string]any{
				"status": "needs_upload", "uploadId": "up_1",
				"parts": []any{map[string]any{"uploadUrl": ts.URL + "/v3/access/uploads/up_1/parts/1", "byteRange": map[string]any{"start": 0, "end": 0}}},
			})
		case "/v3/access/uploads/finalize":
			// mediaId missing: fall back to media.id; duplicates are dropped.
			writeJSON(w, 200, map[string]any{"uploads": []any{
				map[string]any{"uploadId": "up_1", "media": map[string]any{"id": 7}},
				map[string]any{"uploadId": "up_1", "mediaId": 7},
				map[string]any{"uploadId": "up_2", "mediaId": 8},
			}})
		default:
			w.WriteHeader(200)
		}
	})
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: ts.URL})
	result, err := client.UploadMedia(context.Background(), []byte("x"), ofauth.UploadMediaOptions{Filename: "upload.png", ContentType: "image/png", VaultUpload: &ofauth.VaultUpload{UserID: "u1"}})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(result.VaultMediaIDs) != "[7 8]" {
		t.Fatalf("vault media ids = %v", result.VaultMediaIDs)
	}
}

func TestUploadMediaRefusesPartURLsOffTheAPIOrigin(t *testing.T) {
	other := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })
	var ts *testServer
	partURL := ""
	ts = newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.URL.Path == "/v3/access/uploads/start" {
			writeJSON(w, 200, map[string]any{
				"status": "needs_upload", "uploadId": "up_1",
				"parts": []any{map[string]any{"partNumber": 1, "uploadUrl": partURL, "byteRange": map[string]any{"start": 0, "end": 1}}},
			})
			return
		}
		writeJSON(w, 200, map[string]any{"uploadIds": []string{"up_1"}})
	})
	cases := map[string]string{
		"another host":   other.URL + "/v3/access/uploads/up_1/parts/1",
		"another scheme": strings.Replace(ts.URL, "http://", "https://", 1) + "/v3/access/uploads/up_1/parts/1",
		"another port":   "http://127.0.0.1:1/v3/access/uploads/up_1/parts/1",
		"userinfo":       strings.Replace(other.URL, "http://", "http://"+strings.TrimPrefix(ts.URL, "http://")+"@", 1) + "/v3/access/uploads/up_1/parts/1",
		"relative":       "/v3/access/uploads/up_1/parts/1",
	}
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: ts.URL})
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			partURL = u
			before := len(ts.Requests())
			_, err := client.UploadMedia(context.Background(), []byte("01"), ofauth.UploadMediaOptions{Filename: "a.png", ContentType: "image/png"})
			if !errors.Is(err, ofauth.ErrCrossOriginURL) {
				t.Fatalf("err = %v, want ErrCrossOriginURL", err)
			}
			if got := len(ts.Requests()) - before; got != 1 {
				t.Fatalf("API requests = %d, want only the start call", got)
			}
			if n := len(other.Requests()); n != 0 {
				t.Fatalf("other origin got %d requests", n)
			}
		})
	}
}

func TestDoChecksAbsoluteURLsButNotPaths(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) { writeJSON(w, 200, map[string]any{}) })
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("tok"), BaseURL: ts.URL + "/"})
	ctx := context.Background()
	if err := client.Do(ctx, &ofauth.Request{Method: "GET", Path: "/v3/access/profile"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Do(ctx, &ofauth.Request{Method: "GET", Path: "/x", URL: strings.ToUpper(ts.URL[:4]) + ts.URL[4:] + "/v3/x"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Do(ctx, &ofauth.Request{Method: "GET", Path: "/x", URL: "https://api.ofauth.com/v3/x"}, nil); !errors.Is(err, ofauth.ErrCrossOriginURL) {
		t.Fatalf("err = %v", err)
	}
	reqs := ts.Requests()
	if len(reqs) != 2 || reqs[0].Path != "/v3/access/profile" || reqs[1].Path != "/v3/x" {
		t.Fatalf("requests = %+v", reqs)
	}
}
