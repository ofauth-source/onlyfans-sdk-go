package ofauth

// Media uploads: start an upload, PUT each part, then finalize.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// VaultUpload also saves an upload to the vault, optionally into a vault list.
type VaultUpload struct {
	// UserID is the user the vault media is attributed to.
	UserID string `json:"userId"`
	// ListID is an optional vault list to add the media to.
	ListID *int64 `json:"listId,omitempty"`
}

// UploadMediaOptions configures UploadMedia.
type UploadMediaOptions struct {
	// Filename is the original file name, including its extension. Required.
	Filename string
	// ContentType is the MIME type, e.g. image/jpeg or video/mp4. Required.
	ContentType string
	// LinkedAccountID defaults to the client's.
	LinkedAccountID string
	// ETag finds media already in the vault. Defaults to the MD5 hex digest of the file.
	ETag string
	// VaultUpload also saves the upload to the vault.
	VaultUpload *VaultUpload
	// OnProgress is called after each part with the bytes uploaded so far.
	OnProgress func(uploaded, total int64)
}

// Upload statuses.
const (
	UploadStatusAlreadyExists = "already_exists"
	UploadStatusUploaded      = "uploaded"
)

// UploadMediaResult is the outcome of UploadMedia.
type UploadMediaResult struct {
	// Status is UploadStatusAlreadyExists or UploadStatusUploaded.
	Status string
	// MediaID (already_exists) is the existing vault media id. Use it in mediaItems.
	MediaID int64
	// Media (already_exists) is the existing vault media.
	Media *MediaAsset
	// UploadID (uploaded) goes in mediaItems for posts, messages, and stories.
	UploadID string
	// Finalize (uploaded) is the finalize response, with vault media when VaultUpload was set.
	Finalize *AccessUploadsFinalizeResponse
	// VaultMediaIDs (uploaded with VaultUpload) are the vault media ids
	// created for the upload, e.g. to hide them later with
	// Access.Vault.Media.Hide. Empty without VaultUpload.
	VaultMediaIDs []int64
}

// vaultMediaIDs collects the vault media ids from a finalize response
// (uploads[].mediaId, falling back to uploads[].media.id), skipping duplicates.
func vaultMediaIDs(finalize *AccessUploadsFinalizeResponse) []int64 {
	var ids []int64
	seen := map[int64]bool{}
	for _, upload := range finalize.Uploads {
		id := upload.MediaID
		if id == 0 {
			id = upload.Media.ID
		}
		if id != 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// MD5Hex returns the MD5 hex digest of data (the default upload ETag).
func MD5Hex(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// UploadMedia uploads a file: start, upload every part, finalize. Media that
// already exists in the vault is returned without uploading.
//
// Scope: vault:write
func (c *Client) UploadMedia(ctx context.Context, data []byte, opts UploadMediaOptions) (*UploadMediaResult, error) {
	if opts.Filename == "" {
		return nil, errors.New("ofauth: UploadMedia needs a Filename")
	}
	if opts.ContentType == "" {
		return nil, errors.New("ofauth: UploadMedia needs a ContentType")
	}
	etag := opts.ETag
	if etag == "" {
		etag = MD5Hex(data)
	}
	total := int64(len(data))

	var start AccessUploadsStartResponse
	err := c.Do(ctx, &Request{
		Method:          http.MethodPost,
		Path:            "/v3/access/uploads/start",
		Operation:       "access.uploads.start",
		Body:            map[string]any{"filename": opts.Filename, "etag": etag, "size": total, "contentType": opts.ContentType},
		LinkedAccount:   true,
		LinkedAccountID: opts.LinkedAccountID,
	}, &start)
	if err != nil {
		return nil, err
	}

	if start.Status == UploadStatusAlreadyExists {
		result := &UploadMediaResult{Status: UploadStatusAlreadyExists, Media: start.Media}
		if start.Media != nil {
			result.MediaID = start.Media.ID
		}
		return result, nil
	}
	if start.Status != "needs_upload" || start.UploadID == nil || *start.UploadID == "" {
		return nil, fmt.Errorf("ofauth: unexpected upload start status %q", start.Status)
	}
	uploadID := *start.UploadID

	// Part PUTs carry up to several MB each: allow at least UploadPartTimeout per attempt.
	partTimeout := c.timeout()
	if partTimeout > 0 && partTimeout < UploadPartTimeout {
		partTimeout = UploadPartTimeout
	}
	var uploaded int64
	for _, part := range start.Parts {
		from, to := part.ByteRange.Start, part.ByteRange.End+1
		if from < 0 || to > total || from >= to {
			return nil, fmt.Errorf("ofauth: upload part range %d-%d is outside the file", part.ByteRange.Start, part.ByteRange.End)
		}
		u, err := url.Parse(part.UploadURL)
		if err != nil {
			return nil, fmt.Errorf("ofauth: upload part URL: %w", err)
		}
		err = c.Do(ctx, &Request{
			Method:          http.MethodPut,
			Path:            u.Path,
			URL:             part.UploadURL,
			RawBody:         data[from:to],
			Timeout:         partTimeout,
			ContentType:     opts.ContentType,
			LinkedAccount:   true,
			LinkedAccountID: opts.LinkedAccountID,
		}, nil)
		if err != nil {
			return nil, err
		}
		uploaded += to - from
		if opts.OnProgress != nil {
			opts.OnProgress(uploaded, total)
		}
	}

	body := map[string]any{"uploadIds": []string{uploadID}}
	if opts.VaultUpload != nil {
		body["vaultUpload"] = opts.VaultUpload
	}
	var finalize AccessUploadsFinalizeResponse
	err = c.Do(ctx, &Request{
		Method:          http.MethodPost,
		Path:            "/v3/access/uploads/finalize",
		Operation:       "access.uploads.finalize",
		Body:            body,
		LinkedAccount:   true,
		LinkedAccountID: opts.LinkedAccountID,
	}, &finalize)
	if err != nil {
		return nil, err
	}
	return &UploadMediaResult{Status: UploadStatusUploaded, UploadID: uploadID, Finalize: &finalize, VaultMediaIDs: vaultMediaIDs(&finalize)}, nil
}
