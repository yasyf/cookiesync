package bridge

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/yasyf/daemonkit"
	"golang.org/x/sys/unix"
)

// chromeFDTrampoline maps the session onto Chrome's CDP fds 3 and 4 inside /bin/sh.
// A dup2 from Go would overwrite descriptors the runtime still owns there, such as
// darwin's signal pipe or the netpoller, and crash before exec.
const chromeFDTrampoline = `exec "$0" "$@" 3<&0 4>&1`

// RunChromeChild execs Chrome with the daemonkit session as its CDP pipe.
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
	argv := append([]string{"/bin/sh", "-c", chromeFDTrampoline, binary}, chromeArgs(dataDir, headed)...)
	return unix.Exec("/bin/sh", argv, os.Environ())
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
