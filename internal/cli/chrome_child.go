package cli

import (
	"fmt"
	"strconv"

	"github.com/yasyf/cookiesync/internal/bridge"
)

func runChromeChild(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("%s takes <binary> <data-dir> <headed>, got %d args", bridge.ChromeChildVerb, len(args))
	}
	headed, err := strconv.ParseBool(args[2])
	if err != nil {
		return err
	}
	return bridge.RunChromeChild(args[0], args[1], headed)
}
