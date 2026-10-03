package bridge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasyf/daemonkit"
	"golang.org/x/sys/unix"
)

// ChromeChildVerb is the role argument that turns a cookiesync process into the
// Chrome fd adapter. Its entry point dispatches it before the process installs
// any signal handler: on darwin the Go runtime's signal note is a close-on-exec
// pipe at the lowest free descriptors, which in a stdio-only child are fds 3
// and 4, exactly the CDP descriptors Chrome reads.
const ChromeChildVerb = "_bridge-chrome-child"

const (
	cdpCommandFD = 3
	cdpEventFD   = 4
)

// RunChromeChild maps the daemonkit session onto Chrome's CDP descriptors and execs it.
func RunChromeChild(binary, dataDir string, headed bool) error {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return errors.New("bridge: chrome binary must be an exact absolute path")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return errors.New("bridge: chrome data dir must be an exact absolute path")
	}
	if err := daemonkit.CloseInheritedFDs(); err != nil {
		return err
	}
	for _, fd := range []int{cdpCommandFD, cdpEventFD} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			return fmt.Errorf("bridge: fd %d is held by this process; run %s before anything opens a descriptor", fd, ChromeChildVerb)
		}
	}
	if err := unix.Dup2(int(os.Stdin.Fd()), cdpCommandFD); err != nil {
		return fmt.Errorf("bridge: map chrome command fd: %w", err)
	}
	if err := unix.Dup2(int(os.Stdout.Fd()), cdpEventFD); err != nil {
		return fmt.Errorf("bridge: map chrome event fd: %w", err)
	}
	argv := append([]string{binary}, chromeArgs(dataDir, headed)...)
	return unix.Exec(binary, argv, os.Environ())
}

func chromeArgs(dataDir string, headed bool) []string {
	args := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=" + dataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--no-startup-window",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-component-update",
	}
	if !headed {
		args = append(args, "--headless=new")
	}
	return args
}
