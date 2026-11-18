// Command upload uploads a file and posts it.
//
//	OFAUTH_ACCESS_TOKEN=... OFAUTH_LINKED_ACCOUNT_ID=conn_... go run ./examples/upload photo.jpg
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: upload <file>")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	client := ofauth.NewClient(ofauth.Config{
		AccessToken:     ofauth.StaticToken(os.Getenv("OFAUTH_ACCESS_TOKEN")),
		LinkedAccountID: os.Getenv("OFAUTH_LINKED_ACCOUNT_ID"),
	})

	result, err := client.UploadMedia(ctx, data, ofauth.UploadMediaOptions{
		Filename: filepath.Base(os.Args[1]),
		ContentType: http.DetectContentType(data),
		OnProgress:  func(uploaded, total int64) { log.Printf("uploaded %d/%d bytes", uploaded, total) },
	})
	if err != nil {
		log.Fatal(err)
	}

	// mediaItems accepts an upload id, or a vault media id when the file already exists.
	var mediaItem any = result.UploadID
	if result.Status == ofauth.UploadStatusAlreadyExists {
		mediaItem = result.MediaID
	}
	post, err := client.Access.Posts.Create(ctx, ofauth.AccessPostsCreateParams{
		Body: ofauth.AccessPostsCreateBody{Text: ofauth.Ptr("New post"), MediaItems: []any{mediaItem}},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("created post: %+v", post)
}
