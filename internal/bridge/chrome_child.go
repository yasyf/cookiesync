package bridge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yasyf/daemonkit/proc"
	"golang.org/x/sys/unix"
)

// RunChromeChild maps the daemonkit session onto Chrome's CDP descriptors and execs it.
func RunChromeChild(binary, dataDir string, headed bool) error {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return errors.New("bridge: chrome binary must be an exact absolute path")
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return errors.New("bridge: chrome data dir must be an exact absolute path")
	}
	if err := proc.CloseInheritedFDs(); err != nil {
		return err
	}
	if err := unix.Dup2(int(os.Stdin.Fd()), 3); err != nil {
		return fmt.Errorf("bridge: map chrome command fd: %w", err)
	}
	if err := unix.Dup2(int(os.Stdout.Fd()), 4); err != nil {
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
