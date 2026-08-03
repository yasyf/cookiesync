// Package rpc is cookiesync's client to the resident daemon. It is a thin domain
// wrapper over the shared synckit/rpc transport: the generic
// {method, params} -> {ok, result, error} framing, dispatch, peer verification, frame
// bound, and timeouts live in synckit; this package only opens the cookiesync helper's
// business lane and turns a daemon error response into a Go error. The cross-host CLI
// surface (`cookiesync rpc <method> ...`) and the SSH command strings are the frozen
// interop contract; only the intra-host wire is the generic format.
package rpc

import (
	"context"
	"fmt"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/daemonkit"
	"github.com/yasyf/synckit/helperruntime"
	synckit "github.com/yasyf/synckit/rpc"
)

// Call opens the resident daemon's business lane, invokes method with params, and
// returns the decoded result. A daemon-side failure surfaces as a Go error carrying the
// daemon's message; an unreachable daemon is wrapped with the hint to install it.
// params may be nil for a no-arg method.
func Call(ctx context.Context, method string, params map[string]any) (any, error) {
	spec, err := helperruntime.Spec(paths.ToolName, daemonkit.Program{}, 0)
	if err != nil {
		return nil, err
	}
	resident, err := daemonkit.Open(spec)
	if err != nil {
		return nil, err
	}
	if params == nil {
		params = map[string]any{}
	}
	client := synckit.NewClient(synckit.ClientConfig{
		Open: func(context.Context) (*daemonkit.Business, error) { return resident.Business(), nil },
	})
	defer func() { _ = client.Close() }()
	resp, err := client.Call(ctx, &synckit.Request{Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("%w; is the daemon running? (cookiesync install)", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Result, nil
}

// CallJSON invokes method and decodes the result into out via a JSON round-trip, for
// callers that want the typed result rather than the generic any-tree.
func CallJSON(ctx context.Context, method string, params map[string]any, out any) error {
	result, err := Call(ctx, method, params)
	if err != nil {
		return err
	}
	return decode(result, out)
}
