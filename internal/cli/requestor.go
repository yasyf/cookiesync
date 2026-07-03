package cli

import (
	"os"
	"strings"
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
