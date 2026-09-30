package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	synckit "github.com/yasyf/synckit/rpc"
)

func executeImport(t *testing.T, stdin []byte, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := newRoot("test")
	root.SetIn(bytes.NewReader(stdin))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"import"}, args...))
	err := root.ExecuteContext(context.Background())
	return stdout.String(), stderr.String(), err
}

// TestImportSendsTheDocumentVerbatim proves import forwards the stdin bytes unparsed as
// one string param beside the flags, the hosts as given, and the requestor, then prints
// exactly the one success line built from the daemon's reply.
func TestImportSendsTheDocumentVerbatim(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "cookie", "testdata", "import_playwright.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(requestorEnv, "tok")
	var calls []map[string]any
	var methods []string
	orig := rpcCall
	rpcCall = func(_ context.Context, method string, params map[string]any) (any, error) {
		methods = append(methods, method)
		calls = append(calls, params)
		return map[string]any{
			"protocol_version": 1,
			"browser":          "chrome",
			"profile":          "Default",
			"hosts":            []any{"api.third.test", "app.example.test", "www.other.test"},
			"cookies":          3,
			"origins":          1,
			"expires_in":       120,
		}, nil
	}
	t.Cleanup(func() { rpcCall = orig })

	stdout, stderr, err := executeImport(t, document,
		"--format", "playwright", "--ttl", "2m", "--browser", "chrome", "--profile", "Default",
		"--", "app.example.test", "www.other.test", "api.third.test")
	if err != nil {
		t.Fatalf("import: %v\n%s", err, stderr)
	}
	want := map[string]any{
		"browser":   "chrome",
		"profile":   "Default",
		"format":    "playwright",
		"ttl":       "2m",
		"hosts":     []any{"app.example.test", "www.other.test", "api.third.test"},
		"document":  string(document),
		"requestor": "tok",
	}
	if !reflect.DeepEqual(methods, []string{"import"}) || !reflect.DeepEqual(calls, []map[string]any{want}) {
		t.Fatalf("import called %v with %v, want import once with %v", methods, calls, want)
	}
	const wantOut = "imported 3 cookie(s) and 1 origin(s) into chrome/Default for api.third.test, app.example.test, www.other.test (expires in 2m0s)\n"
	if stdout != wantOut {
		t.Fatalf("import stdout = %q, want %q", stdout, wantOut)
	}
	if stderr != "" {
		t.Fatalf("import stderr = %q, want nothing", stderr)
	}
}

// TestImportRefusesBeforeAnyRPC proves every flag, argument, and size refusal fires
// before the daemon is called and leaves stdout empty.
func TestImportRefusesBeforeAnyRPC(t *testing.T) {
	flags := []string{"--format", "playwright", "--ttl", "2m", "--browser", "chrome", "--profile", "Default"}
	withFlags := func(extra ...string) []string {
		return append(append(append([]string{}, flags...), extra...), "--", "app.example.test")
	}
	const tooLarge = "import request exceeds the 16777216-byte RPC payload limit (synckit rpc.MaxPayload)"
	tests := []struct {
		name  string
		args  []string
		stdin []byte
		want  string
	}{
		{
			name: "missing flags",
			args: []string{"--", "app.example.test"},
			want: `required flag(s) "browser", "format", "profile", "ttl" not set`,
		},
		{
			name: "format outside the import formats",
			args: withFlags("--format", "header"),
			want: `unknown import format "header": want playwright or webstorage`,
		},
		{
			name: "ttl past a day",
			args: withFlags("--ttl", "25h"),
			want: "import ttl 25h is outside 1s..24h",
		},
		{
			name: "empty browser",
			args: withFlags("--browser", ""),
			want: "--browser must not be empty",
		},
		{
			name: "empty profile",
			args: withFlags("--profile", ""),
			want: "--profile must not be empty",
		},
		{
			name: "no hosts",
			args: flags,
			want: "requires at least 1 arg(s), only received 0",
		},
		{
			name:  "stdin past the payload limit",
			args:  withFlags(),
			stdin: bytes.Repeat([]byte("a"), synckit.MaxPayload+1),
			want:  tooLarge,
		},
		{
			name:  "stdin under the limit whose escaping passes it",
			args:  withFlags(),
			stdin: bytes.Repeat([]byte(`"`), synckit.MaxPayload-64),
			want:  tooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := rpcCall
			rpcCall = func(_ context.Context, method string, _ map[string]any) (any, error) {
				t.Fatalf("import called %s for a refused request", method)
				return nil, nil
			}
			t.Cleanup(func() { rpcCall = orig })

			stdout, _, err := executeImport(t, tt.stdin, tt.args...)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("import %v error = %v, want %q", tt.args, err, tt.want)
			}
			if stdout != "" {
				t.Fatalf("refused import stdout = %q, want nothing", stdout)
			}
		})
	}
}
