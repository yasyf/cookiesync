package cookie

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Cross-browser cookie fallback via @mherod/get-cookie, swept across every browser.
//
// Used when Chrome self-decrypt finds nothing: the user is logged in via
// Brave/Arc/Edge/Safari/Firefox, or the cookies are app-bound (v20). We deliberately
// omit --browser so get-cookie queries every browser. The package is lazily bun
// add-ed once into a persistent data dir (it needs the native better-sqlite3 module)
// and reused; bunx is the last-resort path.

// GetcookieVersion is the pinned @mherod/get-cookie release; it is load-bearing,
// since the fallback's behaviour and output shape track this version.
const GetcookieVersion = "4.4.3"

// Package is the fully versioned @mherod/get-cookie package spec.
const Package = "@mherod/get-cookie@" + GetcookieVersion

const packageJSON = "{\"name\":\"cookiesync-getcookie-cache\",\"private\":true}\n"

// ErrGetcookie reports that the get-cookie fallback could not run or its output could
// not be parsed.
var ErrGetcookie = errors.New("get-cookie fallback failed")

// dataDir is the persistent cache dir for the lazily installed get-cookie package.
func dataDir() string {
	if cache := os.Getenv("XDG_CACHE_HOME"); cache != "" {
		return filepath.Join(cache, "cookiesync")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".cache", "cookiesync")
	}
	return filepath.Join(home, ".cache", "cookiesync")
}

func cachedCLI() string {
	cli := filepath.Join(dataDir(), "node_modules", "@mherod", "get-cookie", "dist", "cli.cjs")
	if info, err := os.Stat(cli); err == nil && info.Mode().IsRegular() {
		return cli
	}
	return ""
}

// ensureInstalled lazily bun add-s get-cookie into the data dir (building
// better-sqlite3) and returns the cached CLI path, or "" when bun is unavailable.
func ensureInstalled(ctx context.Context) (string, error) {
	if cli := cachedCLI(); cli != "" {
		return cli, nil
	}
	bun, err := exec.LookPath("bun")
	if err != nil {
		return "", nil //nolint:nilerr // a missing bun is a soft miss; the bunx path is tried next.
	}
	data := dataDir()
	if err := os.MkdirAll(data, 0o750); err != nil {
		return "", err
	}
	pkg := filepath.Join(data, "package.json")
	if info, statErr := os.Stat(pkg); statErr != nil || !info.Mode().IsRegular() {
		if err := os.WriteFile(pkg, []byte(packageJSON), 0o644); err != nil { //nolint:gosec // package.json is non-secret manifest content.
			return "", err
		}
	}
	cmd := exec.CommandContext(ctx, bun, "add", Package) //nolint:gosec // bun is resolved via LookPath and Package is a const; the getcookie fallback intentionally shells bun.
	cmd.Dir = data
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: bun add %s: %w", ErrGetcookie, Package, err)
	}
	return cachedCLI(), nil
}

// command returns the argv that runs get-cookie for host across all browsers: the
// cached CLI under bun when available, else bunx, else an error.
func command(ctx context.Context, host Host) ([]string, error) {
	cli, err := ensureInstalled(ctx)
	if err != nil {
		return nil, err
	}
	if cli != "" {
		if bun, lookErr := exec.LookPath("bun"); lookErr == nil {
			return []string{bun, cli, "%", string(host), "--output", "json"}, nil
		}
	}
	if bunx, lookErr := exec.LookPath("bunx"); lookErr == nil {
		return []string{bunx, Package, "%", string(host), "--output", "json"}, nil
	}
	return nil, fmt.Errorf("%w: neither a cached get-cookie nor bun/bunx is available", ErrGetcookie)
}

// decodeAnywhere returns the first JSON value that decodes starting at a "[" or "{"
// in text, tolerating log noise (including brackets) before the JSON value.
func decodeAnywhere(text string) (any, bool) {
	for i, ch := range text {
		if ch != '[' && ch != '{' {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(text[i:]))
		var v any
		if err := dec.Decode(&v); err == nil {
			return v, true
		}
	}
	return nil, false
}

// parse parses get-cookie JSON, tolerating leading log noise before the JSON value
// and unwrapping the {"cookies": [...]} / {"data": [...]} envelopes. A bare object
// is wrapped in a one-element slice.
func parse(stdout string) ([]map[string]any, error) {
	out := strings.TrimSpace(stdout)
	if out == "" {
		return nil, nil
	}
	data, ok := decodeAnywhere(out)
	if !ok {
		return nil, fmt.Errorf("%w: could not parse get-cookie JSON output", ErrGetcookie)
	}
	switch v := data.(type) {
	case map[string]any:
		switch inner := v["cookies"].(type) {
		case []any:
			return toRecords(inner), nil
		}
		switch inner := v["data"].(type) {
		case []any:
			return toRecords(inner), nil
		}
		return []map[string]any{v}, nil
	case []any:
		return toRecords(v), nil
	default:
		return nil, nil
	}
}

func toRecords(items []any) []map[string]any {
	records := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if record, ok := item.(map[string]any); ok {
			records = append(records, record)
		}
	}
	return records
}

// FetchCookies sweeps every browser for host via get-cookie and returns the decoded
// cookies. The exec is bound to ctx so a slow or wedged get-cookie is cancellable.
func FetchCookies(ctx context.Context, host Host) ([]Cookie, error) {
	argv, err := command(ctx, host)
	if err != nil {
		return nil, err
	}
	stdout, err := runGetcookie(ctx, argv)
	if err != nil {
		return nil, err
	}
	records, err := parse(stdout)
	if err != nil {
		return nil, err
	}
	cookies := make([]Cookie, len(records))
	for i, record := range records {
		cookies[i] = NormalizeGetcookieRecord(record, string(host))
	}
	return cookies, nil
}

func runGetcookie(ctx context.Context, argv []string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is the tool's own get-cookie invocation, not user-supplied.
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrGetcookie, err)
	}
	return stdout.String(), nil
}
