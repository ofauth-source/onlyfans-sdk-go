package ofauth_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"strings"
	"testing"

	ofauth "github.com/ofauth-org/onlyfans-sdk-go/v4"
)

// Realtime connections come only from Client.Realtime: nothing exported
// constructs one, and nothing points Realtime anywhere but the BaseURL origin.
func TestRealtimeConnectionsComeOnlyFromAClient(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	prodURL := regexp.MustCompile(`wss?://[A-Za-z0-9]`)
	pkg := pkgs["ofauth"]
	if pkg == nil {
		t.Fatal("package ofauth not found")
	}
	for name, file := range pkg.Files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		// Realtime is Server-Sent Events over net/http: no WebSocket package.
		for _, imp := range file.Imports {
			if strings.Contains(strings.ToLower(imp.Path.Value), "websocket") {
				t.Errorf("%s imports %s", name, imp.Path.Value)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Recv == nil && n.Name.IsExported() && n.Type.Results != nil {
					for _, result := range n.Type.Results.List {
						if strings.Contains(exprString(result.Type), "RealtimeConnection") {
							t.Errorf("%s: exported %s returns a RealtimeConnection without a client", name, n.Name.Name)
						}
					}
				}
			case *ast.Ident:
				if n.IsExported() && (strings.Contains(n.Name, "RealtimeURL") || n.Name == "RealtimeConfig") {
					t.Errorf("%s: exported identifier %s", fset.Position(n.Pos()), n.Name)
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING && prodURL.MatchString(n.Value) {
					t.Errorf("%s: hard-coded WebSocket URL %s", fset.Position(n.Pos()), n.Value)
				}
			}
			return true
		})
	}
	if _, ok := reflect.TypeOf(ofauth.RealtimeOptions{}).FieldByName("URL"); ok {
		t.Error("RealtimeOptions has a URL field")
	}
	for _, field := range reflect.VisibleFields(reflect.TypeOf(ofauth.Config{})) {
		if strings.Contains(field.Name, "Realtime") {
			t.Errorf("Config has a %s field", field.Name)
		}
	}
}

func exprString(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	}
	return ""
}

// Client.Realtime always streams /v3/realtime/events on the BaseURL origin:
// production by default, staging and loopback when BaseURL points there.
func TestClientRealtimeAlwaysUsesTheBaseURLOrigin(t *testing.T) {
	cases := map[string]string{
		"":                                "https://api.ofauth.com/v3/realtime/events?linkedAccountId=conn_1",
		"https://api.staging.ofauth.com":  "https://api.staging.ofauth.com/v3/realtime/events?linkedAccountId=conn_1",
		"https://api.staging.ofauth.com/": "https://api.staging.ofauth.com/v3/realtime/events?linkedAccountId=conn_1",
		"http://127.0.0.1:1":              "http://127.0.0.1:1/v3/realtime/events?linkedAccountId=conn_1",
	}
	for baseURL, want := range cases {
		var got []string
		client := ofauth.NewClient(ofauth.Config{
			AccessToken: ofauth.StaticToken("tok"), LinkedAccountID: "conn_1", BaseURL: baseURL,
			OnRequest: func(info ofauth.RequestInfo) { got = append(got, info.URL) },
		})
		rt, err := client.Realtime(ofauth.RealtimeOptions{DisableReconnect: true})
		if err != nil {
			t.Fatal(err)
		}
		// Cancelled before dialing: the attempt is reported, nothing goes over the network.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := rt.Connect(ctx); err == nil {
			t.Fatalf("BaseURL %q: want a connect error", baseURL)
		}
		if len(got) != 1 || got[0] != want {
			t.Fatalf("BaseURL %q: realtime URL = %v, want %s", baseURL, got, want)
		}
	}
}
