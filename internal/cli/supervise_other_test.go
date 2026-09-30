//go:build !linux

package cli

import "testing"

// TestSuperviseIsLinuxOnly proves no supervise command exists off Linux, where
// synckitd drives the helper through launchd.
func TestSuperviseIsLinuxOnly(t *testing.T) {
	for _, cmd := range newRoot("test").Commands() {
		if cmd.Name() == "supervise" {
			t.Fatal("root registers supervise off Linux")
		}
	}
}
