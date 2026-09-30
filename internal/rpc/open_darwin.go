package rpc

import (
	"context"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/synckit/helperruntime"

	"github.com/yasyf/cookiesync/internal/paths"
)

func open(context.Context) (*daemonkit.Client, error) {
	spec, err := helperruntime.Spec(paths.ToolName, daemonkit.Program{}, 0)
	if err != nil {
		return nil, err
	}
	return daemonkit.Open(spec)
}
