package cli

import (
	"os"
	"testing"
)

// TestRootWiresPayloadToStdout proves newRoot points cobra's payload writer at stdout and
// its error writer at stderr, so cmd.Println output pipes rather than landing on stderr.
func TestRootWiresPayloadToStdout(t *testing.T) {
	root := newRoot("test")
	if got := root.OutOrStderr(); got != os.Stdout {
		t.Errorf("root OutOrStderr() = %v, want os.Stdout", got)
	}
	if got := root.ErrOrStderr(); got != os.Stderr {
		t.Errorf("root ErrOrStderr() = %v, want os.Stderr", got)
	}
}

// TestSubcommandInheritsStdout proves a child resolves the same writers through the parent
// chain — the load-bearing case, since payload commands like cookies are subcommands.
func TestSubcommandInheritsStdout(t *testing.T) {
	root := newRoot("test")
	subs := root.Commands()
	if len(subs) == 0 {
		t.Fatal("newRoot has no subcommands")
	}
	child := subs[0]
	if got := child.OutOrStderr(); got != os.Stdout {
		t.Errorf("%s OutOrStderr() = %v, want os.Stdout (inherited from root)", child.Name(), got)
	}
	if got := child.ErrOrStderr(); got != os.Stderr {
		t.Errorf("%s ErrOrStderr() = %v, want os.Stderr (inherited from root)", child.Name(), got)
	}
}
