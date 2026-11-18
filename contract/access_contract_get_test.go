package contract_test

// Contract tests for every GET Access operation in accessEndpoints.manifest.json.
//
// Each manifest entry names its SDK method (`sdk`, e.g.
// "access.chats.messages.list"); the test calls that generated method through
// reflection, so it checks both the route and that the response decodes into
// the generated types.
//
// Environment:
//   E2E_ACCESS_BASE_URL     API origin, e.g. https://api.staging.ofauth.com
//   E2E_ACCESS_TOKEN        bearer access token
//                           preferred in CI instead of E2E_ACCESS_TOKEN: mint
//   E2E_LINKED_ACCOUNT_ID   linked account to act on
//   E2E_CONTRACT_REQUIRED=1 fail (instead of skip) when the above are missing
//   E2E_CONTRACT_STRICT=1   fail when an endpoint could not be exercised
//   E2E_MIN_DELAY_MS        minimum delay between requests
//   E2E_SDK_SUITES          comma-separated suites to run (default: all)

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

type endpointSpec struct {
	Method  string `json:"method"`
	Route   string `json:"route"`
	Tag     string `json:"tag"`
	Summary string `json:"summary"`
	Scope   string `json:"scope"`
	SDK     string `json:"sdk"`
}

var routeParam = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

// fixtureSources lists, per route param, the list route whose first item supplies it.
var fixtureSources = map[string][]string{
	"userId":         {"/chats", "/subscribers"},
	"postId":         {"/posts"},
	"listId":         {"/lists"},
	"vaultListId":    {"/vault/lists"},
	"massMessageId":  {"/analytics/mass-messages/sent"},
	"promotionId":    {"/promotions"},
	"bundleId":       {"/promotions/bundles"},
	"trackingLinkId": {"/promotions/tracking-links"},
	"trialLinkId":    {"/promotions/trial-links"},
	"storyId":        {"/stories"},
	"highlightId":    {"/stories/highlights"},
	"mediaId":        {"/vault/media"},
	"subscriptionId": {"/subscriptions"},
	"subscriberId":   {"/subscribers"},
	"releaseFormId":  {"/release-forms"},
	"labelId":        {"/users/labels"},
	"categoryId":     {"/posts/bookmarks/categories"},
	"commentId":      {"/posts/{postId}/comments"},
	"messageId":      {"/chats/{userId}/messages"},
	"settingId":      {"/settings"},
	"buttonId":       {"/profile/social-buttons"},
	"linkId":         {"/profile/links"},
	"scheduleId":     {"/queue/schedules"},
}

func loadDotEnvLocal() {
	// Optional: load .env.e2e.local from the current or a parent directory,
	// without overriding variables that are already set.
	for _, p := range []string{".env.e2e.local", "../.env.e2e.local", "../../.env.e2e.local", "../../../.env.e2e.local"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, val, ok := strings.Cut(line, "=")
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if !ok || key == "" {
				continue
			}
			if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
				val = val[1 : len(val)-1]
			}
			if _, set := os.LookupEnv(key); !set {
				_ = os.Setenv(key, val)
			}
		}
		return
	}
}

func envFlag(name string) bool {
	v := os.Getenv(name)
	return v == "1" || strings.EqualFold(v, "true")
}

func shouldRunSuite(name string) bool {
	suites := strings.TrimSpace(os.Getenv("E2E_SDK_SUITES"))
	if suites == "" {
		return true
	}
	for _, s := range strings.Split(suites, ",") {
		if strings.TrimSpace(s) == name {
			return true
		}
	}
	return false
}

var initialisms = map[string]string{"id": "ID", "ids": "IDs", "url": "URL", "urls": "URLs", "uri": "URI", "api": "API", "qr": "QR", "oauth": "OAuth", "json": "JSON", "html": "HTML", "ip": "IP", "md5": "MD5", "etag": "ETag"}

// goName mirrors the generator's naming: "massMessages" -> "MassMessages", "getQr" -> "GetQR".
func goName(raw string) string {
	var b strings.Builder
	for _, part := range regexp.MustCompile(`[^A-Za-z0-9]+`).Split(regexp.MustCompile(`([a-z0-9])([A-Z])`).ReplaceAllString(raw, "$1 $2"), -1) {
		if part == "" {
			continue
		}
		if mapped, ok := initialisms[strings.ToLower(part)]; ok {
			b.WriteString(mapped)
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// sdkMethod resolves "access.chats.messages.list" to the bound method.
func sdkMethod(client *ofauth.Client, sdk string) (reflect.Value, error) {
	segments := strings.Split(sdk, ".")
	v := reflect.ValueOf(client)
	for _, seg := range segments[:len(segments)-1] {
		f := v.Elem().FieldByName(goName(seg))
		if !f.IsValid() {
			return reflect.Value{}, fmt.Errorf("namespace %s not found", seg)
		}
		v = f
	}
	m := v.MethodByName(goName(segments[len(segments)-1]))
	if !m.IsValid() {
		return reflect.Value{}, fmt.Errorf("method %s not found", sdk)
	}
	return m, nil
}

func setField(params reflect.Value, name string, value string) bool {
	f := params.FieldByName(goName(name))
	if !f.IsValid() || !f.CanSet() {
		return false
	}
	target := f
	if f.Kind() == reflect.Pointer {
		target = reflect.New(f.Type().Elem()).Elem()
	}
	switch target.Kind() {
	case reflect.String:
		target.SetString(value)
	case reflect.Int64:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return false
		}
		target.SetInt(n)
	case reflect.Float64:
		n, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}
		target.SetFloat(n)
	case reflect.Bool:
		target.SetBool(value == "true")
	case reflect.Interface:
		target.Set(reflect.ValueOf(value))
	default:
		return false
	}
	if f.Kind() == reflect.Pointer {
		f.Set(target.Addr())
	}
	return true
}

// defaultQuery fills common required or helpful query params.
func defaultQuery(route string) map[string]string {
	q := map[string]string{"limit": "1"}
	if strings.Contains(route, "/analytics/") || strings.Contains(route, "timeseries") || strings.HasSuffix(route, "/top") {
		end := time.Now().UTC()
		q["startDate"] = end.AddDate(0, 0, -30).Format("2006-01-02")
		q["endDate"] = end.Format("2006-01-02")
	}
	if route == "/users/search" {
		q["query"] = "test"
	}
	return q
}

func firstItemValue(resp any, param string) (string, bool) {
	data, err := json.Marshal(resp)
	if err != nil {
		return "", false
	}
	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil {
		return "", false
	}
	var list []any
	for _, key := range []string{"items", "list", "data"} {
		if l, ok := obj[key].([]any); ok {
			list = l
			break
		}
	}
	if len(list) == 0 {
		return "", false
	}
	first, ok := list[0].(map[string]any)
	if !ok {
		return "", false
	}
	if param == "userId" {
		for _, key := range []string{"withUser", "user"} {
			if u, ok := first[key].(map[string]any); ok && u["id"] != nil {
				return fmt.Sprint(u["id"]), true
			}
		}
	}
	for _, key := range []string{"id", param} {
		if v, ok := first[key]; ok && v != nil {
			if f, isFloat := v.(float64); isFloat {
				return strconv.FormatFloat(f, 'f', -1, 64), true
			}
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

func TestAccessGetContractGeneratedSDK(t *testing.T) {
	if !shouldRunSuite("access-get") {
		t.Skip("suite disabled via E2E_SDK_SUITES")
	}
	loadDotEnvLocal()

	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("E2E_ACCESS_BASE_URL")), "/")
	baseURL = strings.TrimSuffix(strings.TrimSuffix(baseURL, "/v3/access"), "/v3")
	linkedAccountID := strings.TrimSpace(os.Getenv("E2E_LINKED_ACCOUNT_ID"))
	var tokens ofauth.TokenSource
	if token := strings.TrimSpace(os.Getenv("E2E_ACCESS_TOKEN")); token != "" {
		tokens = ofauth.StaticToken(token)
	}
	if baseURL == "" || tokens == nil || linkedAccountID == "" {
		const want = "E2E_ACCESS_BASE_URL, E2E_LINKED_ACCOUNT_ID, and E2E_ACCESS_TOKEN"
		if envFlag("E2E_CONTRACT_REQUIRED") {
			t.Fatal("set " + want)
		}
		t.Skip("no e2e credentials (set " + want + ")")
	}

	raw, err := os.ReadFile("accessEndpoints.manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest []endpointSpec
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	byRoute := map[string]endpointSpec{}
	var gets []endpointSpec
	for _, e := range manifest {
		if strings.EqualFold(e.Method, "get") {
			gets = append(gets, e)
			byRoute[e.Route] = e
		}
	}
	if len(gets) < 20 {
		t.Fatalf("unexpected manifest GET endpoint count: %d", len(gets))
	}

	minDelay := time.Duration(0)
	if ms, err := strconv.Atoi(os.Getenv("E2E_MIN_DELAY_MS")); err == nil {
		minDelay = time.Duration(ms) * time.Millisecond
	}
	client := ofauth.NewClient(ofauth.Config{
		AccessToken:     tokens,
		LinkedAccountID: linkedAccountID,
		BaseURL:         baseURL,
		HTTPClient:      &http.Client{Timeout: 60 * time.Second},
	})
	ctx := context.Background()
	var lastCall time.Time

	call := func(e endpointSpec, pathValues map[string]string) (any, error) {
		if wait := minDelay - time.Since(lastCall); wait > 0 {
			time.Sleep(wait)
		}
		lastCall = time.Now()
		method, err := sdkMethod(client, e.SDK)
		if err != nil {
			return nil, err
		}
		params := reflect.New(method.Type().In(1)).Elem()
		for name, value := range defaultQuery(e.Route) {
			setField(params, name, value)
		}
		for name, value := range pathValues {
			if !setField(params, name, value) {
				return nil, fmt.Errorf("cannot set path param %s", name)
			}
		}
		out := method.Call([]reflect.Value{reflect.ValueOf(ctx), params})
		if errV := out[len(out)-1]; !errV.IsNil() {
			return nil, errV.Interface().(error)
		}
		if len(out) == 2 {
			return out[0].Interface(), nil
		}
		return nil, nil
	}

	fixtures := map[string]string{}
	var resolve func(route, param string, depth int) (string, bool)
	resolve = func(route, param string, depth int) (string, bool) {
		key := param
		if param == "listId" && strings.HasPrefix(route, "/vault/") {
			key = "vaultListId"
		}
		if v, ok := fixtures[key]; ok {
			return v, v != ""
		}
		fixtures[key] = ""
		if depth > 2 {
			return "", false
		}
		for _, source := range fixtureSources[key] {
			e, ok := byRoute[source]
			if !ok {
				continue
			}
			values, ok := resolveAll(source, depth+1, resolve)
			if !ok {
				continue
			}
			resp, err := call(e, values)
			if err != nil {
				t.Logf("fixture %s from %s: %v", key, source, err)
				continue
			}
			if v, ok := firstItemValue(resp, param); ok {
				fixtures[key] = v
				return v, true
			}
		}
		return "", false
	}

	remaining := map[string]bool{}
	for _, e := range gets {
		remaining[e.SDK] = true
	}
	for _, e := range gets {
		values, ok := resolveAll(e.Route, 0, resolve)
		if !ok {
			t.Logf("skip %s %s: no fixture", e.Route, e.SDK)
			continue
		}
		if _, err := call(e, values); err != nil {
			t.Errorf("GET %s (%s): %v", e.Route, e.SDK, err)
			continue
		}
		delete(remaining, e.SDK)
	}

	if envFlag("E2E_CONTRACT_STRICT") && len(remaining) > 0 {
		missing := make([]string, 0, len(remaining))
		for name := range remaining {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		t.Fatalf("%d GET Access endpoints not exercised:\n- %s", len(missing), strings.Join(missing, "\n- "))
	}
}

func resolveAll(route string, depth int, resolve func(route, param string, depth int) (string, bool)) (map[string]string, bool) {
	values := map[string]string{}
	for _, m := range routeParam.FindAllStringSubmatch(route, -1) {
		v, ok := resolve(route, m[1], depth)
		if !ok {
			return nil, false
		}
		values[m[1]] = v
	}
	return values, true
}

// TestManifestMethodsExist runs offline: every manifest entry must map to a
// generated method that takes (context.Context, Params).
func TestManifestMethodsExist(t *testing.T) {
	raw, err := os.ReadFile("accessEndpoints.manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest []endpointSpec
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	client := ofauth.NewClient(ofauth.Config{AccessToken: ofauth.StaticToken("unused")})
	for _, e := range manifest {
		if e.SDK == "" {
			t.Errorf("%s %s: no sdk name", e.Method, e.Route)
			continue
		}
		m, err := sdkMethod(client, e.SDK)
		if err != nil {
			t.Errorf("%s %s: %v", e.Method, e.Route, err)
			continue
		}
		if m.Type().NumIn() != 2 {
			t.Errorf("%s: expected (ctx, params), got %s", e.SDK, m.Type())
			continue
		}
		params := m.Type().In(1)
		for _, p := range routeParam.FindAllStringSubmatch(e.Route, -1) {
			if _, ok := params.FieldByName(goName(p[1])); !ok {
				t.Errorf("%s: params %s has no field for {%s}", e.SDK, params.Name(), p[1])
			}
		}
	}
}
