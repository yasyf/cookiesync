package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestBrowserAddChecksAPeerAgainstEveryPlatformsBrowsers(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seedRegistry(t, "me@laptop", "you@desktop")

	if got := runBrowserCmd(t, "add", "you@desktop", "arc"); strings.TrimSpace(got) != "Tracking you@desktop:arc:Default" {
		t.Fatalf("add peer arc = %q, want Tracking you@desktop:arc:Default", got)
	}

	root := newRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"browser", "add", "you@desktop", "nope"})
	err := root.ExecuteContext(context.Background())
	if want := `unknown browser "nope"; choose from arc, chrome`; err == nil || err.Error() != want {
		t.Fatalf("add peer unknown browser = %v, want %s", err, want)
	}
}
