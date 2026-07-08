package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const requestorEnv = "COOKIESYNC_REQUESTOR"

// agentSessions is the ordered list of recognized agent-session identities. The first
// whose idEnv is set names the requestor; nameEnv (when set) supplies a friendly short
// reference in place of the raw id.
var agentSessions = []struct{ label, idEnv, nameEnv string }{
	{"Claude Code", "CLAUDE_CODE_SESSION_ID", ""}, // no session-name env exists today
}

// resolveRequestor returns the stable requestor token for grant reuse, or ("", false)
// to let the daemon fall back to the login session / local. COOKIESYNC_REQUESTOR wins.
func resolveRequestor() (string, bool) {
	if r := os.Getenv(requestorEnv); r != "" {
		return r, true
	}
	for _, a := range agentSessions {
		if id := os.Getenv(a.idEnv); id != "" {
			ref := ""
			if a.nameEnv != "" {
				ref = os.Getenv(a.nameEnv)
			}
			if ref == "" {
				ref = shortRef(id)
			}
			return a.label + " · " + ref, true
		}
	}
	return "", false
}

// shortRef reduces a session id to a stable short reference: the segment before the
// first "-", capped at eight characters. It never panics on a short or hyphenless id.
func shortRef(id string) string {
	before, _, _ := strings.Cut(id, "-")
	if len(before) > 8 {
		before = before[:8]
	}
	return before
}

// requestorToken is resolveRequestor with a never-empty tail: outside a recognized
// agent session it falls back to the parent process id, so callers that key durable
// state on the token (e.g. a per-session cloud browser) always get a value.
func requestorToken() string {
	if r, ok := resolveRequestor(); ok {
		return r
	}
	return fmt.Sprintf("pid-%d", os.Getppid())
}

// newRequestorCmd prints the stable requestor token — the same identity that keys
// grant reuse — so external tools can scope per-session state to this caller.
func newRequestorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "requestor",
		Short: "Print the stable requestor token for this session (grant-reuse identity).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println(requestorToken())
			return nil
		},
	}
}
