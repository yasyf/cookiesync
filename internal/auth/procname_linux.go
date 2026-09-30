//go:build linux

package auth

import (
	"context"
	"os"
	"strconv"
)

func processName(_ context.Context, pid int) (string, error) {
	out, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	return string(out), err
}
