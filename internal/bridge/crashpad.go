package bridge

import (
	"path/filepath"
	"slices"
	"strings"
)

const (
	crashpadDatabaseDir = "Crashpad"
	crashpadDatabaseArg = "--database="
)

func crashpadDatabase(dataDir string) string {
	return filepath.Join(dataDir, crashpadDatabaseDir)
}

func servesCrashpadDatabase(argv []string, database string) bool {
	return len(argv) > 1 && slices.Contains(argv[1:], crashpadDatabaseArg+database)
}

func parseCmdline(cmdline []byte) []string {
	return strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
}
