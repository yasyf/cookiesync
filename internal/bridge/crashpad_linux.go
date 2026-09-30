//go:build linux

package bridge

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	crashpadDiscoveryWindow = 3 * time.Second
	crashpadDiscoveryPoll   = 250 * time.Millisecond
	crashpadExitTimeout     = 5 * time.Second
	crashpadTermGrace       = 2 * time.Second
	crashpadKillGrace       = time.Second
)

// Chrome keys its crash database off the default profile location and ignores
// --user-data-dir (crbug.com/40447560); BREAKPAD_DUMP_LOCATION is its supported
// override, and it is what puts this session's dataDir into every crashpad
// handler's argv.
func crashpadEnvironment(dataDir, nonce string) []string {
	return []string{"BREAKPAD_DUMP_LOCATION=" + crashpadDatabase(dataDir), launchEnv + "=" + nonce}
}

type handlerRecord struct {
	procStat
	pid     int
	cmdline []string
	exe     string
}

func (r handlerRecord) String() string {
	return fmt.Sprintf("ppid %d pgid %d sid %d start %d exe %q argv %q", r.ppid, r.pgid, r.sid, r.start, r.exe, r.cmdline)
}

type ownedHandler struct {
	handlerRecord
	pidfd int
}

type preservedCandidate struct {
	handlerRecord
	reason error
}

type handlerTracker struct {
	database    string
	nonce       string
	exitTimeout time.Duration
	termGrace   time.Duration
	killGrace   time.Duration
	stop        chan struct{}
	settled     chan struct{}

	mu        sync.Mutex
	owned     map[int]ownedHandler
	preserved map[int]preservedCandidate
	err       error
}

func trackHandlers(dataDir, nonce string) *handlerTracker {
	t := &handlerTracker{
		database:    crashpadDatabase(dataDir),
		nonce:       nonce,
		exitTimeout: crashpadExitTimeout,
		termGrace:   crashpadTermGrace,
		killGrace:   crashpadKillGrace,
		stop:        make(chan struct{}),
		settled:     make(chan struct{}),
		owned:       map[int]ownedHandler{},
	}
	go t.discover()
	return t
}

func (t *handlerTracker) discover() {
	defer close(t.settled)
	window := time.NewTimer(crashpadDiscoveryWindow)
	defer window.Stop()
	ticker := time.NewTicker(crashpadDiscoveryPoll)
	defer ticker.Stop()
	for {
		t.adopt()
		select {
		case <-t.stop:
			return
		case <-window.C:
			return
		case <-ticker.C:
		}
	}
}

func (t *handlerTracker) adopt() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.record(fmt.Errorf("bridge: list /proc: %w", err))
		return
	}
	preserved := map[int]preservedCandidate{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || t.owns(pid) || !t.serves(pid) {
			continue
		}
		record, err := t.pin(pid)
		if err != nil && t.serves(pid) {
			preserved[pid] = preservedCandidate{handlerRecord: record, reason: err}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.preserved = preserved
}

func (t *handlerTracker) pin(pid int) (handlerRecord, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return handlerRecord{pid: pid}, fmt.Errorf("pin: %w", err)
	}
	record, err := t.examine(pid)
	if err != nil {
		_ = unix.Close(pidfd)
		return record, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.owned[pid] = ownedHandler{handlerRecord: record, pidfd: pidfd}
	return record, nil
}

func (t *handlerTracker) examine(pid int) (handlerRecord, error) {
	record := handlerRecord{pid: pid}
	argv, err := readCmdline(pid)
	if err != nil {
		return record, err
	}
	record.cmdline = argv
	stat, err := os.ReadFile(procPath(pid, "stat"))
	if err != nil {
		return record, err
	}
	identity, err := parseProcStat(stat)
	if err != nil {
		return record, err
	}
	record.procStat = identity
	exe, err := os.Readlink(procPath(pid, "exe"))
	if err != nil {
		return record, err
	}
	record.exe = exe
	environ, err := os.ReadFile(procPath(pid, "environ"))
	if err != nil {
		return record, err
	}
	if !servesCrashpadDatabase(record.cmdline, t.database) {
		return record, errors.New("its command line stopped serving the database")
	}
	if err := verifyLaunchEvidence(environ, t.nonce); err != nil {
		return record, err
	}
	return record, verifyHandlerExe(record.exe)
}

func (t *handlerTracker) serves(pid int) bool {
	argv, err := readCmdline(pid)
	return err == nil && servesCrashpadDatabase(argv, t.database)
}

func (t *handlerTracker) owns(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.owned[pid]
	return ok
}

func (t *handlerTracker) record(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.err = errors.Join(t.err, err)
}

func (t *handlerTracker) tracked() []int {
	<-t.settled
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Sorted(maps.Keys(t.owned))
}

func (t *handlerTracker) close() error {
	close(t.stop)
	<-t.settled
	t.adopt()
	t.mu.Lock()
	defer t.mu.Unlock()
	handlers := slices.SortedFunc(maps.Values(t.owned), func(a, b ownedHandler) int { return cmp.Compare(a.pid, b.pid) })
	err := errors.Join(t.err, reap(handlers, t.exitTimeout, t.termGrace, t.killGrace))
	for _, h := range handlers {
		err = errors.Join(err, unix.Close(h.pidfd))
	}
	for _, pid := range slices.Sorted(maps.Keys(t.preserved)) {
		candidate := t.preserved[pid]
		err = errors.Join(err, fmt.Errorf("bridge: refused to reap crashpad candidate %d serving %s%s (%s): %w",
			pid, crashpadDatabaseArg, t.database, candidate.handlerRecord, candidate.reason))
	}
	return err
}

func readCmdline(pid int) ([]string, error) {
	cmdline, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil {
		return nil, err
	}
	return splitNUL(cmdline), nil
}

func procPath(pid int, file string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + file
}

func reap(handlers []ownedHandler, exitTimeout, termGrace, killGrace time.Duration) error {
	alive, err := awaitExit(handlers, exitTimeout)
	if err != nil {
		return err
	}
	alive, err = signalAndAwait(alive, unix.SIGTERM, termGrace)
	if err != nil {
		return err
	}
	alive, err = signalAndAwait(alive, unix.SIGKILL, killGrace)
	if err != nil {
		return err
	}
	errs := make([]error, 0, len(alive))
	for _, h := range alive {
		errs = append(errs, fmt.Errorf("bridge: crashpad handler %d (%s) survived SIGKILL", h.pid, h.handlerRecord))
	}
	return errors.Join(errs...)
}

func signalAndAwait(handlers []ownedHandler, sig unix.Signal, grace time.Duration) ([]ownedHandler, error) {
	for _, h := range handlers {
		if err := unix.PidfdSendSignal(h.pidfd, sig, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return nil, fmt.Errorf("bridge: send %s to crashpad handler %d: %w", sig, h.pid, err)
		}
	}
	return awaitExit(handlers, grace)
}

func awaitExit(handlers []ownedHandler, timeout time.Duration) ([]ownedHandler, error) {
	deadline := time.Now().Add(timeout)
	pending := handlers
	for len(pending) > 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		fds := make([]unix.PollFd, len(pending))
		for i, h := range pending {
			fds[i] = unix.PollFd{Fd: int32(h.pidfd), Events: unix.POLLIN} //nolint:gosec // G115: a pidfd is a descriptor, which the kernel bounds to int32.
		}
		n, err := unix.Poll(fds, int(remaining.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bridge: poll crashpad handlers: %w", err)
		}
		if n == 0 {
			break
		}
		still := make([]ownedHandler, 0, len(pending))
		for i, h := range pending {
			if fds[i].Revents&unix.POLLIN == 0 {
				still = append(still, h)
			}
		}
		pending = still
	}
	return pending, nil
}
