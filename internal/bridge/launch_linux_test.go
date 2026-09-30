package bridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	chromeWrapperScript = "#!/bin/bash\nexec -a \"$0\" \"$(dirname \"$0\")/chrome\" \"$@\"\n"
	snapShimScript      = "#!/bin/sh\nif ! [ -x /snap/bin/chromium ]; then\n  exit 1\nfi\nexec /snap/bin/chromium \"$@\"\n"
)

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture must be executable.
		t.Fatal(err)
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestResolveHostBinaryPrefersTheFirstCandidateOnPath(t *testing.T) {
	root := resolvedTempDir(t)
	bin := filepath.Join(root, "bin")
	writeExecutable(t, filepath.Join(bin, "chromium"), chromeWrapperScript)
	writeExecutable(t, filepath.Join(bin, "google-chrome"), chromeWrapperScript)
	t.Setenv("PATH", bin)

	got, err := ResolveHostBinary()
	if err != nil {
		t.Fatalf("ResolveHostBinary: %v", err)
	}
	if want := filepath.Join(bin, "google-chrome"); got != want {
		t.Fatalf("ResolveHostBinary() = %q, want %q", got, want)
	}
}

func TestResolveHostBinaryFollowsSymlinksToTheExactFile(t *testing.T) {
	root := resolvedTempDir(t)
	target := filepath.Join(root, "opt", "google", "chrome", "google-chrome")
	writeExecutable(t, target, chromeWrapperScript)
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(bin, "google-chrome-stable")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	got, err := ResolveHostBinary()
	if err != nil {
		t.Fatalf("ResolveHostBinary: %v", err)
	}
	if got != target || !filepath.IsAbs(got) || filepath.Clean(got) != got {
		t.Fatalf("ResolveHostBinary() = %q, want the exact absolute target %q", got, target)
	}
}

func TestResolveHostBinarySkipsSnapShims(t *testing.T) {
	root := resolvedTempDir(t)
	bin := filepath.Join(root, "bin")
	writeExecutable(t, filepath.Join(bin, "chromium"), snapShimScript)
	writeExecutable(t, filepath.Join(bin, "chromium-browser"), chromeWrapperScript)
	t.Setenv("PATH", bin)

	got, err := ResolveHostBinary()
	if err != nil {
		t.Fatalf("ResolveHostBinary: %v", err)
	}
	if want := filepath.Join(bin, "chromium-browser"); got != want {
		t.Fatalf("ResolveHostBinary() = %q, want the non-snap %q", got, want)
	}
}

func TestResolveHostBinaryFailsActionablyWithNoChrome(t *testing.T) {
	root := resolvedTempDir(t)
	bin := filepath.Join(root, "bin")
	writeExecutable(t, filepath.Join(bin, "chromium-browser"), snapShimScript)
	t.Setenv("PATH", bin)

	got, err := ResolveHostBinary()
	if err == nil {
		t.Fatalf("ResolveHostBinary() = %q, want an error when only a snap shim exists", got)
	}
	for _, want := range []string{"google-chrome-stable, google-chrome, chromium, chromium-browser", "snap", "install google-chrome-stable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ResolveHostBinary() error = %q, want it to mention %q", err, want)
		}
	}
}

func TestSnapStub(t *testing.T) {
	root := resolvedTempDir(t)
	tests := []struct {
		name   string
		binary string
		body   string
		want   bool
	}{
		{name: "snap mount", binary: "/snap/bin/chromium", want: true},
		{name: "snap launcher", binary: "/usr/bin/snap", want: true},
		{name: "shell shim execing a snap", binary: filepath.Join(root, "shim"), body: snapShimScript, want: true},
		{name: "chrome wrapper script", binary: filepath.Join(root, "wrapper"), body: chromeWrapperScript, want: false},
		{name: "binary mentioning snap without a shebang", binary: filepath.Join(root, "elf"), body: "\x7fELF/snap/", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.body != "" {
				writeExecutable(t, tt.binary, tt.body)
			}
			got, err := snapStub(tt.binary)
			if err != nil {
				t.Fatalf("snapStub(%q): %v", tt.binary, err)
			}
			if got != tt.want {
				t.Fatalf("snapStub(%q) = %v, want %v", tt.binary, got, tt.want)
			}
		})
	}
}
