# OFAuth Go SDK

Import `github.com/ofauth-org/onlyfans-sdk-go/v4`. The package provides typed resource clients, iterators, errors, uploads, webhook verification, server Realtime, and standard OAuth helpers.

```go
client := ofauth.NewClient(ofauth.Config{
    AccessToken: ofauth.TokenFunc(func(ctx context.Context, forceRefresh bool) (string, error) {
        return currentAccessToken(ctx, forceRefresh)
    }),
    LinkedAccountID: selectedAccountID,
})
profile, err := client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{})

link := ofauth.NewLink(ofauth.LinkConfig{ClientID: clientID, ClientSecret: secret, RedirectURI: callbackURI})
pending, err := link.CreateAuthorizationURL(ofauth.AuthorizationURLOptions{Scopes: []ofauth.Scope{ofauth.ScopeProfileRead}})
// Save pending under your trusted user and session before redirecting to pending.URL.
callback, err := link.ParseCallback(callbackURL, pending.State)
tokens, err := link.ExchangeCode(ctx, ofauth.ExchangeCodeOptions{Code: callback.Code, CodeVerifier: pending.CodeVerifier})
renewed, err := link.Refresh(ctx, ofauth.RefreshOptions{RefreshToken: tokens.RefreshToken})
err = link.Revoke(ctx, ofauth.RevokeOptions{Token: tokens.RefreshToken, TokenTypeHint: "refresh_token"})
```

Handle each error before the next step. `StaticToken` supplies a fixed bearer. `TokenFunc` delegates renewal to your auth system. Set `LinkConfig.ClientAuthentication` to `client_secret_post` to use form credentials.

## OAuth contract

Register a confidential backend client and an exact callback URL. Sandbox, Test, and Live use the same authorization code flow with S256 PKCE.

- Browser authorization: `https://link.ofauth.com/v3/authorize`.
- Token exchange and refresh: `POST https://api.ofauth.com/v3/link/token` with a form body.
- Revocation: `POST https://api.ofauth.com/v3/link/revoke` with form `token` and optional `token_type_hint`.
- Metadata: `https://api.ofauth.com/.well-known/oauth-authorization-server/v3/link`.
- Profile: `GET https://api.ofauth.com/v3/link/userinfo` with `identity:read`.

Code exchange always returns a refresh token. Access tokens are opaque Bearer secrets with a 900-second lifetime. Use the returned `expires_in`. Refresh echoes the same client-bound refresh token and extends its 90-day inactivity window. Independent processes can refresh concurrently and retry after a lost response.

The helper uses `client_secret_basic` by default and also supports `client_secret_post`. Each request uses one method. Keep client secrets and refresh tokens on your backend and send them only to OAuth endpoints.

Bind fresh state and the PKCE verifier to the initiating application user and session. Persist pending state in your application, expire it, and consume it once after validating the session. Callback helpers validate the expected state and issuer and reject duplicate parameters. A lost initial code response requires a new authorization attempt.

Your auth framework owns token persistence and renewal. Supply its current access token or token getter to the resource client. The SDK does not provide a second credential manager or database schema. Without a framework, store the standard token response in your database and call the small OAuth helper near expiry. Condition writes on a registration revision so an in-flight refresh cannot overwrite a replacement or recreate a deleted registration. Refresh concurrency does not require a distributed lock.

Discover accounts through `GET /v3/linked-accounts`, then select one explicitly. Token responses do not contain account lists. Client construction sends no requests. An account ID selects a resource; it does not grant authority.

Refresh-token revocation ends that credential and its access tokens. Access-token revocation ends only that bearer. `DELETE /v3/authorization` disconnects the entire authorization. Provider reconnect repairs one selected provider session through `POST /v3/linked-accounts/{id}/reconnect`; it does not renew OAuth or replay writes.

Resource errors distinguish invalid bearer, insufficient permission, account selection, provider reconnect, quota, and transient failure. Follow the error's recovery action. Authenticated requests reject redirects. When injecting a custom transport, preserve this redirect policy; in C#, configure `HttpClientHandler.AllowAutoRedirect = false`.

Developer calls use the application's Developer entitlement. Owners grant account access and do not need an Operator subscription. Operator uses its holder's allowance and cannot access Realtime or Vault+.

See [the public documentation](https://docs.ofauth.com) for consent, grants, guest connection, account linking, and release availability. This branch is coordinated with [OAuth foundation #1274](https://github.com/seb-lewis/ofauth-mono/issues/1274) and requires the matching issuer release.

## Linked accounts

Every Access and Vault+ call targets one linked account, sent as `x-linked-account-id`. Set a default on the client, override it per call with the `LinkedAccountID` param, or bind a copy of the client. Calls without one fail locally with `ofauth.ErrLinkedAccountRequired`.

```go
client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{LinkedAccountID: "conn_other"})
other := client.WithLinkedAccount("conn_other")

for account, err := range client.LinkedAccounts.Iterate(ctx, ofauth.LinkedAccountsListParams{}) {
	if err != nil {
		return err
	}
	fmt.Println(account.ID, account.Status)
}
client.LinkedAccounts.Remove(ctx, ofauth.LinkedAccountsRemoveParams{ID: "conn_1"})
```
## Operations

Operations are grouped by path: `client.Access.<Area>...<Method>(ctx, params)`. Each method takes a `<Namespace><Method>Params` struct: path and query parameters are fields, the JSON body is `Body`, and the doc comment names the HTTP route and scope.

```go
client.Access.Posts.Create(ctx, ofauth.AccessPostsCreateParams{Body: ofauth.AccessPostsCreateBody{Text: ofauth.Ptr("New post")}})
client.Access.Users.Search(ctx, ofauth.AccessUsersSearchParams{Query: ofauth.Ptr("creator")})
client.Access.Finances.Earnings.Transactions.List(ctx, ofauth.AccessFinancesEarningsTransactionsListParams{Limit: ofauth.Ptr(int64(20))})
client.VaultPlus.Lists.Sync(ctx, ofauth.VaultPlusListsSyncParams{ListID: "123"})
```

Cursor-paginated operations have an `Iterate*` companion returning `iter.Seq2[Item, error]`. It fetches pages as you go and stops when there are no more pages; break out of the loop or pass `ofauth.MaxItems(n)` to stop early:

```go
for chat, err := range client.Access.Chats.Iterate(ctx, ofauth.AccessChatsListParams{Limit: ofauth.Ptr(int64(20))}, ofauth.MaxItems(100)) {
	if err != nil {
		return err
	}
	fmt.Println(chat.User.ID)
}
```

`client.Do(ctx, &ofauth.Request{...}, &out)` is the low-level call the generated methods use; it applies the same auth, linked-account header, retry, and error handling. `Request.MaxRetries` and `Request.Timeout` override the client config for one call.

### Retries and timeouts

```go
client := ofauth.NewClient(ofauth.Config{
	AccessToken:   manager,
	MaxRetries:    ofauth.Ptr(3),     // default 2 (DefaultMaxRetries); ofauth.Ptr(0) disables retries
	Timeout:       30 * time.Second, // per attempt, default 60s; negative disables
	MaxRetryDelay: time.Minute,      // longest server-requested wait, default 60s
})
```

A failed attempt is retried when:

- the request failed without a response because of the network (`net.Error`, DNS, `ECONNRESET`/`ECONNREFUSED`, unexpected EOF) or the per-attempt timeout, and the method is `GET`, `HEAD`, or `OPTIONS`;
- the status is `429` (any method);
- the status is `503` with `authorization_temporarily_unavailable` (any method: rejected before execution);
- the status is `502`, `503`, or `504` otherwise, and the method is `GET`, `HEAD`, or `OPTIONS`.

Other `4xx` are never retried, and nothing is retried once `ctx` is done. Any other error from `HTTPClient`'s transport (e.g. a custom `http.RoundTripper` refusing a request by policy) is returned unchanged after one attempt: no retry, no `*ConnectionError` wrapping. The delay is `Retry-After` (seconds or HTTP date), else `RateLimit-Reset` (seconds), else `0.5s * 2^retry` with full jitter, capped at 8s. When the server asks to wait longer than `MaxRetryDelay` (e.g. `429 quota_exhausted` until the quota resets), the error is returned instead. The one-time `invalid_token` refresh is separate and not counted. OAuth token, revoke, webhook, and Realtime calls are not retried. Upload part PUTs use a per-attempt timeout of at least 300s (`UploadPartTimeout`).

`APIError.Attempts` / `ConnectionError.Attempts` report how many attempts were made.

### Hooks and debug logging

```go
client := ofauth.NewClient(ofauth.Config{
	AccessToken: manager,
	OnRequest:   func(info ofauth.RequestInfo) { /* Method, URL, Header (credentials redacted), Attempt */ },
	OnResponse:  func(info ofauth.ResponseInfo) { /* Method, URL, StatusCode, RequestID, Duration, Attempt, Err */ },
	Debug:       true, // or DebugLogger: func(line string) { slog.Debug(line) }
})
```

Hooks and errors never carry credentials, so they are safe to log. `Header` redacts `Authorization`, `Cookie`, `X-Api-Key`, `Cf-Access-Client-Secret`, and any header whose name contains `token`, `secret`, or `password`, whatever the casing. `URL` (also `ConnectionError.URL` and the `*url.Error` inside transport errors) has the values of credential-like query parameters (`X-Amz-Signature` and other `X-Amz-*`, `token`, `sig`, `key`, ...) replaced by `REDACTED`; the request itself is sent unchanged. `Config.Header` and `Request.Header` cannot set `Authorization` (requests fail with `ErrAuthorizationHeader`): the SDK sends the bearer token itself.

Debug logging (also enabled by `OFAUTH_DEBUG=1`) writes one line per attempt plus retry notices, never tokens, secrets, or bodies:

```
[ofauth] GET /v3/access/profile -> 503 (41ms, req_abc)
[ofauth] retrying GET /v3/access/profile in 412ms (retry 1/2)
[ofauth] GET /v3/access/profile -> 200 (38ms, req_abd)
```

Hooks run synchronously on the calling goroutine; a panicking hook is recovered and ignored.

`client.Realtime(...)` uses the same hooks and debug logger for each stream attempt: `OnRequest` gets `GET`, the sanitized `/v3/realtime/events` URL, and the headers with Authorization redacted; `OnResponse` gets status `200` when the stream opens, the HTTP status when it is refused, or `0` with `Err` when there was no response, plus the duration and `x-realtime-session-id` (or `x-request-id`):

```
[ofauth] SSE /v3/realtime/events -> 200 (85ms, rts_abc)
```

### Types

Params, bodies, and responses are generated structs:

- Optional fields and nullable values are pointers (`ofauth.Ptr(v)` builds one); slices and maps are left nil when absent.
- `integer` is `int64`; `number` is `float64`, except id-like fields (`id`, `userId`, `mediaIds`, ...) which are `int64`.
- Union schemas: inline object variants merge into one struct; same-kind scalars collapse; unions of different JSON kinds (e.g. `string | number`, `object | array`) are `any` and decode to `map[string]any`, `[]any`, `float64`, `string`, or `bool`. Use `ofauth.Decode[T](v)` to convert such a value into a struct.
- Enum fields are plain strings; their doc comments list the allowed values.
## Errors

Access, Vault+, and linked-account failures return `*ofauth.APIError`. Branch on `RecoveryAction` (an `ofauth.RecoveryAction` string; the `RecoveryAction*` constants list the known values, unknown ones are kept as-is) or the helper methods, not on the HTTP status alone:

```go
_, err := client.Access.Profile.Get(ctx, ofauth.AccessProfileGetParams{})
var apiErr *ofauth.APIError
if errors.As(err, &apiErr) {
	switch {
	case apiErr.NeedsReconnect(): // reconnect_linked_account: the owner must reconnect the account
	case apiErr.NeedsReauthorization(): // restart_authorization, request_additional_consent, grant_linked_account
		scopes := ofauth.MissingScopes(err) // [RequiredScope] for missing_scope / additional_consent_required
	case apiErr.NeedsTokenRefresh(): // obtain_external_oauth_token
	case apiErr.IsIntegrationProblem(): // complete_integration_approval, update_developer_plan, contact_integration_owner, enable_vault_plus
	case apiErr.IsRetryable(): // retry, retry_after_reset, or 429/502/503/504: wait apiErr.RetryAfter
	}
	log.Println(apiErr.StatusCode, apiErr.Code, apiErr.Operation, apiErr.RequiredScope, apiErr.RequestID, apiErr.Attempts)
}
```

`Operation` is the canonical name of the failed call and `RequiredScope` its scope. `ofauth.NeedsReauthorization(err)` checks any error chain (`*APIError`, `*OAuthError` with `invalid_grant`, `*ReauthorizationRequiredError`). Network failures, per-attempt timeouts, and `ctx` cancellation (after retries) are `*ofauth.ConnectionError`, which unwraps to the cause (`errors.Is(err, context.DeadlineExceeded)`). Errors your own transport returns are passed through as-is.

Error bodies come in three documented shapes, all normalized onto `Code`:

- `RuntimeError` (`{"error", "recovery", "requestId"}`): `Code` is `error`, `RecoveryAction` is `recovery.action`.
- `RequestValidationError` (a query, path, or body parameter failed validation): `Code` is `invalid_request`, `RecoveryAction` is `check_request`, `Issues []ValidationIssue` lists each failure (`Code`, `Path`, `Message`), and `Message` reads like `limit: Number must be less than or equal to 100`.
- `AccessHandlerError` (`{"error": "<message>", "type": "RESOURCE_NOT_FOUND"}`, from some Access handlers such as uploads): `Code` is the lower-cased `type` (`resource_not_found`), `ErrorType` keeps the raw class, `Message` is the `error` text, and `RecoveryAction` is empty (the helpers fall back to the status).

`ofauth.IsAPIError(err, "reconnect_linked_account")` matches a code or recovery action. `APIError.Body` holds the raw response. See [Errors](https://docs.ofauth.com/v3/errors) for every code and action.
## Webhooks

Deliveries use [Standard Webhooks](https://www.standardwebhooks.com) signatures (`svix-*` headers are accepted too). `WebhookRouter` verifies the raw body, routes by `type`, and is an `http.Handler` (200 on success, 401 `{"error": code}` on failed verification, 500 when a handler returns an error):

```go
router := ofauth.NewWebhookRouter(os.Getenv("OFAUTH_WEBHOOK_SECRET"))
router.OnAuthorizationRevoked(func(ctx context.Context, e *ofauth.LifecycleAuthorizationRevokedEnvelope) error {
	return db.DeleteTokens(ctx, e.AuthorizationID)
})
router.OnRealtimeChatMessageReceived(func(ctx context.Context, e *ofauth.RealtimeChatMessageReceivedEnvelope) error {
	return handleMessage(e.Data)
})
router.OnDefault(func(ctx context.Context, e *ofauth.WebhookEvent) error { return nil })
http.Handle("/webhooks/ofauth", router)
```

There is a typed `On<Type>` method for every event type, plus `router.On(ofauth.EventLinkedAccountExpired, handler)` with the raw `*WebhookEvent`. To verify yourself: `event, err := ofauth.VerifyWebhook(rawBody, r.Header, secret, 0)`; failures are `*ofauth.WebhookVerificationError` with `Code` (`MISSING_HEADERS`, `INVALID_TIMESTAMP`, `TIMESTAMP_OUT_OF_TOLERANCE`, `NO_VALID_SIGNATURES`, `SIGNATURE_MISMATCH`, `INVALID_JSON`).

Deduplicate on `EventID` and apply events per `LinkedAccountID` in `Order`.

### Testing webhook handlers

The `ofauthtest` package builds valid envelopes for all 17 event types (from the OpenAPI examples) and signs them:

```go
import "github.com/ofauth-org/onlyfans-sdk-go/v4/ofauthtest"

router := newRouter(ofauthtest.WebhookSecret) // a valid whsec_ test secret
event, err := ofauthtest.CreateTestEvent(ofauth.EventAuthorizationRevoked, map[string]any{
	"authorizationId": "authz_123", // deep-merged; eventId is fresh unless overridden
})
_, err = ofauthtest.Deliver(ctx, router, ofauthtest.WebhookSecret, event) // sign + router.Handle

// Or through ServeHTTP:
signed, err := ofauthtest.SignWebhook(event, ofauthtest.WebhookSecret, ofauthtest.WithID("msg_1"), ofauthtest.WithTimestamp(time.Now()))
rec := httptest.NewRecorder()
router.ServeHTTP(rec, signed.Request("/webhooks/ofauth")) // signed.Header + signed.Body
```
## Realtime

Receive Realtime events for one linked account over Server-Sent Events: `client.Realtime` streams `GET /v3/realtime/events` with the client's token source, `HTTPClient`, and extra `Header`, using `net/http` (no extra dependency).

```go
rt, err := client.Realtime(ofauth.RealtimeOptions{LinkedAccountID: "conn_1", LastEventID: saved})
rt.OnRealtimeChatMessageReceived(func(e *ofauth.RealtimeEvent, d *ofauth.RealtimeChatMessageReceivedData) {
	fmt.Println(d.ID)
})
rt.OnResync(func() { refetchEverything() }) // events were missed: refetch through the REST API
rt.OnClose(func(info ofauth.RealtimeCloseInfo) { log.Println(info.Reason, info.Status, info.WillReconnect, info.RetryIn) })
if err := rt.Connect(ctx); err != nil { // a failed first attempt returns the error (e.g. 409 or 503 as *APIError)
	return err
}
<-rt.Done() // closed after rt.Close(), ctx cancellation, or a final close; see rt.Err()
saved = rt.LastEventID()
```

- **Resume and dedupe:** reconnects send `Last-Event-ID` (the last event's `Order`), and repeated `EventID`s are dropped (delivery is at least once). `RealtimeOptions.LastEventID` resumes after a restart.
- **Reconnects:** after a drop or a transient outage, the connection waits for the server's `retry:` time (3 s by default) × 2^failures with jitter, capped at `MaxReconnectDelay` (30 s) and never shorter than `Retry-After`. `DisableReconnect` turns this off.
- **Heartbeat:** the server sends a comment every 15 s; when nothing arrives for `HeartbeatTimeout` (45 s, negative to disable), the stream is treated as dead and resumed. The timeout also bounds the wait for the response headers. `Config.Timeout` and `HTTPClient.Timeout` do not apply to the stream.
- **Close reasons** (`RealtimeCloseInfo.Reason`, a `RealtimeCloseReason`):
  - `reauth` (closed with `reauth`, or 401): forces a token refresh (`AccessToken(ctx, true)`) and retries once, then stops. A `StaticToken` stops at once on 401.
  - `replaced` (closed with `replaced`, or 409): a newer stream took the slot (up to 10 per account). Stops.
  - `unavailable` (closed with `unavailable`, 429, 5xx): backs off and resumes.
  - `dropped` (the stream ended without `closed`, or a network error) and `heartbeat_timeout`: resume.
  - `rejected` (other 4xx, a non-event-stream response, or an error from your transport): stops.
  - `client_closed`: `Close()` or the `Connect` context ended.

  `Status` is the HTTP status of a refused stream, and `RetryIn` the delay before the next attempt.
- `Connect` while connected waits for that connection instead of opening another; after the connection stopped, it starts again. Handlers run on the connection's goroutine.

`client.Realtime` is the only way to get a `*RealtimeConnection`. It always streams `/v3/realtime/events` on the `BaseURL` origin. Realtime is served on the same origin as every other API route, so there is no realtime URL setting and a staging client never sends its token to production Realtime. A `BaseURL` that is not http(s) makes `client.Realtime` return an error.

### Realtime in a browser

Browsers must never hold the access token. Mint a stream URL on your server and send only the URL to the page, which opens it with `EventSource` (or `connectRealtimeStream` from `@ofauth/onlyfans-sdk/realtime-browser`):

```go
stream, err := client.CreateRealtimeStreamURL(ctx, ofauth.CreateRealtimeStreamURLParams{}) // POST /v3/realtime
// stream.URL carries a 10-minute stream credential (not the access token); stream.ExpiresAt
```
## Uploads

```go
upload, err := client.UploadMedia(ctx, fileBytes, ofauth.UploadMediaOptions{Filename: "photo.jpg", ContentType: "image/jpeg"})
var mediaItem any = upload.UploadID
if upload.Status == ofauth.UploadStatusAlreadyExists {
	mediaItem = upload.MediaID
}
client.Access.Posts.Create(ctx, ofauth.AccessPostsCreateParams{
	Body: ofauth.AccessPostsCreateBody{Text: ofauth.Ptr("New photo"), MediaItems: []any{mediaItem}},
})
```

`UploadMedia` starts the upload (with the file's MD5 as `etag` for vault dedupe), PUTs each part, and finalizes it. Files already in the vault are returned without uploading: `MediaID` and `Media` (`*ofauth.MediaAsset`) describe the existing media. Set `VaultUpload: &ofauth.VaultUpload{UserID: ...}` to save the upload to the vault, and `OnProgress` to track bytes sent. `Finalize` is the typed finalize response (`*ofauth.AccessUploadsFinalizeResponse`), and `VaultMediaIDs` collects the vault media ids it created (`uploads[].mediaId`), e.g. to hide them later:

```go
upload, err := client.UploadMedia(ctx, fileBytes, ofauth.UploadMediaOptions{Filename: "photo.jpg", ContentType: "image/jpeg", VaultUpload: &ofauth.VaultUpload{UserID: "123"}})
client.Access.Vault.Media.Hide(ctx, ofauth.AccessVaultMediaHideParams{Body: ofauth.AccessVaultMediaHideBody{MediaIDs: upload.VaultMediaIDs}})
```
## API reference

The reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ofauth-org/onlyfans-sdk-go/v4), generated from the doc comments: every operation's comment names its route, scope, canonical operation name, and a one-line usage example. Browse it locally with `go doc -all github.com/ofauth-org/onlyfans-sdk-go/v4` (or `go run golang.org/x/pkgsite/cmd/pkgsite@latest` for HTML). `TestExportedIdentifiersHaveDocComments` fails when an exported identifier, generated or hand-written, has no doc comment.
## Development

The package is generated: run `pnpm generate:types && node scripts/generate-go.mjs` from the repository root (needs `gofmt` on `PATH`). Hand-written runtime files live in `scripts/templates/go/`. Then:

```bash
cd packages/go && gofmt -l . && go vet ./... && go test -race ./...
```

Contract tests in `contract/` call every GET Access operation listed in `contract/accessEndpoints.manifest.json` and skip unless `E2E_ACCESS_BASE_URL`, `E2E_ACCESS_TOKEN`, and `E2E_LINKED_ACCOUNT_ID` are set.
