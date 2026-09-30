//go:build !linux

package cli

import "testing"

// TestImportIsLinuxOnly proves no import command exists off Linux, where a Mac exports
// the documents a Linux helper imports.
func TestImportIsLinuxOnly(t *testing.T) {
	for _, cmd := range newRoot("test").Commands() {
		if cmd.Name() == "import" {
			t.Fatal("root registers import off Linux")
		}
	}
}
