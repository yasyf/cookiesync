package rpc

import (
	"encoding/json"
	"fmt"
)

// decode re-encodes the generic result any-tree and unmarshals it into out, so a
// caller reads a typed struct off the wire without hand-walking the map.
func decode(result, out any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("re-encode rpc result: %w", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode rpc result: %w", err)
	}
	return nil
}
