//go:build darwin

package auth

import (
	"context"
	"os/exec"
	"strconv"
)

func processName(ctx context.Context, pid int) (string, error) {
	out, err := exec.CommandContext(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: pid is an int rendered to string, not user-supplied text; no injection surface.
	return string(out), err
}
