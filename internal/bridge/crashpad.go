package bridge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	crashpadDatabaseDir = "Crashpad"
	crashpadDatabaseArg = "--database="
	crashpadHandlerExe  = "chrome_crashpad_handler"
	launchEnv           = "COOKIESYNC_BRIDGE_LAUNCH"

	statFieldState = 3
	statFieldPPID  = 4
	statFieldPGID  = 5
	statFieldSID   = 6
	statFieldStart = 22
)

type procStat struct {
	ppid  int
	pgid  int
	sid   int
	start uint64
}

func crashpadDatabase(dataDir string) string {
	return filepath.Join(dataDir, crashpadDatabaseDir)
}

func newLaunchNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate launch nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func servesCrashpadDatabase(argv []string, database string) bool {
	return len(argv) > 1 && slices.Contains(argv[1:], crashpadDatabaseArg+database)
}

func verifyLaunchEvidence(environ []byte, nonce string) error {
	entries := splitNUL(environ)
	if slices.Contains(entries, launchEnv+"="+nonce) {
		return nil
	}
	if slices.ContainsFunc(entries, func(entry string) bool { return strings.HasPrefix(entry, launchEnv+"=") }) {
		return errors.New("its environment carries another launch's " + launchEnv)
	}
	return errors.New("its environment carries no " + launchEnv)
}

func verifyHandlerExe(exe string) error {
	if filepath.Base(exe) == crashpadHandlerExe {
		return nil
	}
	return fmt.Errorf("its executable %s is not %s", exe, crashpadHandlerExe)
}

func splitNUL(list []byte) []string {
	return strings.Split(strings.TrimSuffix(string(list), "\x00"), "\x00")
}

func parseProcStat(stat []byte) (procStat, error) {
	comm := bytes.LastIndexByte(stat, ')')
	if comm < 0 {
		return procStat{}, fmt.Errorf("bridge: /proc stat %q names no comm", stat)
	}
	fields := strings.Fields(string(stat[comm+1:]))
	if len(fields) < statFieldStart-statFieldState+1 {
		return procStat{}, fmt.Errorf("bridge: /proc stat %q stops before field %d", stat, statFieldStart)
	}
	ppid, err := strconv.Atoi(fields[statFieldPPID-statFieldState])
	if err != nil {
		return procStat{}, fmt.Errorf("bridge: /proc stat ppid: %w", err)
	}
	pgid, err := strconv.Atoi(fields[statFieldPGID-statFieldState])
	if err != nil {
		return procStat{}, fmt.Errorf("bridge: /proc stat pgid: %w", err)
	}
	sid, err := strconv.Atoi(fields[statFieldSID-statFieldState])
	if err != nil {
		return procStat{}, fmt.Errorf("bridge: /proc stat sid: %w", err)
	}
	start, err := strconv.ParseUint(fields[statFieldStart-statFieldState], 10, 64)
	if err != nil {
		return procStat{}, fmt.Errorf("bridge: /proc stat start time: %w", err)
	}
	return procStat{ppid: ppid, pgid: pgid, sid: sid, start: start}, nil
}
