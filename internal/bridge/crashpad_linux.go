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

func withCrashpadEnvironment(base []string, dataDir, nonce string) []string {
	return append(slices.DeleteFunc(base, carriesLaunch), crashpadEnvironment(dataDir, nonce)...)
}

type handlerRecord struct {
	procStat
	cmdline []string
	exe     string
}

func (r handlerRecord) String() string {
	return fmt.Sprintf("ppid %d pgid %d sid %d start %d exe %q argv %q", r.ppid, r.pgid, r.sid, r.start, r.exe, r.cmdline)
}

type pin struct {
	pid   int
	pidfd int
}

func pinCandidate(pid int) (pin, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return pin{}, fmt.Errorf("bridge: pin crashpad candidate %d: %w", pid, err)
	}
	return pin{pid: pid, pidfd: pidfd}, nil
}

func (p pin) alive() (bool, error) {
	fds := []unix.PollFd{exitPoll(p.pidfd)}
	for {
		_, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("bridge: poll crashpad candidate %d: %w", p.pid, err)
		}
		return fds[0].Revents&unix.POLLIN == 0, nil
	}
}

func (p pin) release() error {
	return unix.Close(p.pidfd)
}

type ownedHandler struct {
	handlerRecord
	pin
}

type preservedCandidate struct {
	handlerRecord
	reason error
}

func (c preservedCandidate) present(pid int) (bool, error) {
	candidate, err := pinCandidate(pid)
	if errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = candidate.release() }()
	stat, readErr := os.ReadFile(procPath(pid, "stat")) //nolint:gosec // G703: pid is a decimal int rendered into /proc/<pid>/stat, which cannot traverse.
	alive, err := candidate.alive()
	if err != nil || !alive {
		return false, err
	}
	if readErr != nil {
		return false, readErr
	}
	identity, err := parseProcStat(stat)
	if err != nil {
		return false, err
	}
	return identity.start == c.start, nil
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
	t.expire()
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
		candidate, err := pinCandidate(pid)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			t.record(err)
			continue
		}
		record, verdict := t.examine(candidate)
		alive, err := candidate.alive()
		if err != nil {
			t.record(err)
		}
		if !alive {
			_ = candidate.release()
			continue
		}
		if verdict == nil {
			t.own(ownedHandler{handlerRecord: record, pin: candidate})
			continue
		}
		_ = candidate.release()
		if servesCrashpadDatabase(record.cmdline, t.database) {
			preserved[pid] = preservedCandidate{handlerRecord: record, reason: verdict}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.preserved = preserved
}

func (t *handlerTracker) expire() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid, h := range t.owned {
		alive, err := h.alive()
		if err != nil {
			t.err = errors.Join(t.err, err)
			continue
		}
		if alive {
			continue
		}
		delete(t.owned, pid)
		t.err = errors.Join(t.err, h.release())
	}
}

func (t *handlerTracker) examine(candidate pin) (handlerRecord, error) {
	var record handlerRecord
	argv, err := readCmdline(candidate.pid)
	if err != nil {
		return record, err
	}
	record.cmdline = argv
	stat, err := os.ReadFile(procPath(candidate.pid, "stat"))
	if err != nil {
		return record, err
	}
	identity, err := parseProcStat(stat)
	if err != nil {
		return record, err
	}
	record.procStat = identity
	exe, err := os.Readlink(procPath(candidate.pid, "exe"))
	if err != nil {
		return record, err
	}
	record.exe = exe
	environ, err := os.ReadFile(procPath(candidate.pid, "environ"))
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

func (t *handlerTracker) own(h ownedHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.owned[h.pid] = h
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
		err = errors.Join(err, h.release())
	}
	return errors.Join(err, refusals(t.preserved, t.database))
}

func refusals(preserved map[int]preservedCandidate, database string) error {
	var err error
	for _, pid := range slices.Sorted(maps.Keys(preserved)) {
		candidate := preserved[pid]
		present, presentErr := candidate.present(pid)
		if presentErr == nil && !present {
			continue
		}
		err = errors.Join(err, presentErr, fmt.Errorf("bridge: refused to reap crashpad candidate %d serving %s%s (%s): %w",
			pid, crashpadDatabaseArg, database, candidate.handlerRecord, candidate.reason))
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

func exitPoll(pidfd int) unix.PollFd {
	return unix.PollFd{Fd: int32(pidfd), Events: unix.POLLIN} //nolint:gosec // G115: a pidfd is a descriptor, which the kernel bounds to int32.
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
			fds[i] = exitPoll(h.pidfd)
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
