package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/synckit/helperruntime"
	synckit "github.com/yasyf/synckit/rpc"

	"github.com/yasyf/cookiesync/internal/daemon"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/testutil"
)

const importTooLarge = "import request exceeds the 16777216-byte RPC payload limit (synckit rpc.MaxPayload)"

type idleProduct struct{}

func (idleProduct) Drain(context.Context) error { return nil }

func (idleProduct) Close(context.Context) error { return nil }

func serveImportHelper(t *testing.T) *synckit.Client {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "cs-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("DAEMONKIT_HOME", home)

	runtime, err := helperruntime.New(helperruntime.Config{
		App:        helperruntime.App{Name: paths.ToolName},
		Dispatcher: daemon.New(nil, nil, nil, nil, nil, nil, nil).Dispatcher(),
		Prepare:    func(daemonkit.Ctx) (helperruntime.Product, error) { return idleProduct{}, nil },
	})
	if err != nil {
		t.Fatalf("helperruntime.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- runtime.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("helper runtime: %v", err)
			}
		case <-time.After(45 * time.Second):
			t.Error("helper runtime did not settle after cancellation")
		}
	})

	spec, err := daemon.HelperSpec()
	if err != nil {
		t.Fatalf("daemon.HelperSpec: %v", err)
	}
	if spec.MaxFrame != synckit.MaxFrame {
		t.Fatalf("helper MaxFrame = %d, want synckit's %d", spec.MaxFrame, synckit.MaxFrame)
	}
	client, err := daemonkit.Open(spec)
	if err != nil {
		t.Fatalf("open resident helper: %v", err)
	}
	lane := synckit.NewClient(synckit.ClientConfig{
		Open: func(context.Context) (*daemonkit.Business, error) { return client.Business(), nil },
	})
	t.Cleanup(func() { _ = lane.Close() })
	deadline := time.Now().Add(30 * time.Second)
	for {
		probeCtx, probeCancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := lane.Call(probeCtx, &synckit.Request{Method: "__cookiesync_readiness_probe__"})
		probeCancel()
		if err == nil {
			return lane
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper never dispatched: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

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
			want:  importTooLarge,
		},
		{
			name:  "stdin under the limit whose escaping passes it",
			args:  withFlags(),
			stdin: bytes.Repeat([]byte(`"`), synckit.MaxPayload-64),
			want:  importTooLarge,
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

// TestImportRequestFitsTheHelperFrame proves the CLI's payload bound fits the helper's
// real frame: served under the helper's spec, an import whose encoded request is exactly
// synckit.MaxPayload crosses the transport whole and the daemon imports it, and one byte
// more is refused before anything is sent.
func TestImportRequestFitsTheHelperFrame(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	t.Setenv(requestorEnv, "tok")
	fixture, err := os.ReadFile(filepath.Join("..", "cookie", "testdata", "import_playwright.json"))
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{"app.example.test", "www.other.test", "api.third.test"}
	padded := func(n int) string { return "{" + strings.Repeat(" ", n) + string(fixture[1:]) }
	unpadded, err := synckit.EncodeRequest(&synckit.Request{Method: "import", Params: map[string]any{
		"browser": "chrome", "profile": "Default", "format": "playwright", "ttl": "1m",
		"hosts": asAnySlice(hosts), "document": padded(0), "requestor": "tok",
	}})
	if err != nil {
		t.Fatal(err)
	}
	fill := synckit.MaxPayload - len(unpadded)

	lane := serveImportHelper(t)
	var sent []int
	orig := rpcCall
	rpcCall = func(ctx context.Context, method string, params map[string]any) (any, error) {
		req := &synckit.Request{Method: method, Params: params}
		body, err := synckit.EncodeRequest(req)
		if err != nil {
			return nil, err
		}
		sent = append(sent, len(body))
		resp, err := lane.Call(ctx, req)
		if err != nil {
			return nil, err
		}
		if !resp.OK {
			return nil, errors.New(resp.Error)
		}
		return resp.Result, nil
	}
	t.Cleanup(func() { rpcCall = orig })

	tests := []struct {
		name     string
		fill     int
		wantSent []int
		wantOut  string
		wantErr  string
	}{
		{
			name:     "exactly MaxPayload crosses the frame and is imported",
			fill:     fill,
			wantSent: []int{synckit.MaxPayload},
			wantOut:  "imported 3 cookie(s) and 1 origin(s) into chrome/Default for api.third.test, app.example.test, www.other.test (expires in 1m0s)\n",
		},
		{
			name:    "one byte past MaxPayload is refused before sending",
			fill:    fill + 1,
			wantErr: importTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sent = nil
			args := append([]string{"--format", "playwright", "--ttl", "1m", "--browser", "chrome", "--profile", "Default", "--"}, hosts...)
			stdout, _, err := executeImport(t, []byte(padded(tt.fill)), args...)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Fatalf("import error = %q, want %q", gotErr, tt.wantErr)
			}
			if stdout != tt.wantOut {
				t.Fatalf("import stdout = %q, want %q", stdout, tt.wantOut)
			}
			if !reflect.DeepEqual(sent, tt.wantSent) {
				t.Fatalf("encoded requests sent = %v, want %v", sent, tt.wantSent)
			}
		})
	}
}
