package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// agentBrowserProtocol tags every agent-browser plugin message on the wire.
const agentBrowserProtocol = "agent-browser.plugin.v1"

// pluginRequest is the exec-once envelope agent-browser writes to the plugin's stdin.
type pluginRequest struct {
	Protocol   string          `json:"protocol"`
	Type       string          `json:"type"`
	Capability string          `json:"capability"`
	Request    json.RawMessage `json:"request"`
}

// pluginLaunchRequest is the browser.launch request body.
type pluginLaunchRequest struct {
	Provider      string `json:"provider"`
	Session       string `json:"session"`
	LaunchOptions struct {
		Headed bool   `json:"headed"`
		Engine string `json:"engine"`
	} `json:"launchOptions"`
}

// pluginCleanup is the client-side bridge endpoint key echoed between browser.launch and browser.close.
type pluginCleanup struct {
	Endpoint string `json:"endpoint"`
}

// pluginManifest is the plugin.manifest reply's descriptor.
type pluginManifest struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	Description  string   `json:"description"`
}

// pluginBrowser is the browser.launch reply's connection descriptor.
type pluginBrowser struct {
	CDPURL     string        `json:"cdpUrl"`
	DirectPage bool          `json:"directPage"`
	Cleanup    pluginCleanup `json:"cleanup"`
}

type pluginManifestResponse struct {
	Protocol string         `json:"protocol"`
	Success  bool           `json:"success"`
	Manifest pluginManifest `json:"manifest"`
}

type pluginLaunchResponse struct {
	Protocol string        `json:"protocol"`
	Success  bool          `json:"success"`
	Browser  pluginBrowser `json:"browser"`
}

type pluginOKResponse struct {
	Protocol string `json:"protocol"`
	Success  bool   `json:"success"`
}

type pluginErrorResponse struct {
	Protocol string `json:"protocol"`
	Success  bool   `json:"success"`
	Error    string `json:"error"`
}

// newBridgePluginCmd builds the hidden agent-browser provider adapter: an
// exec-once JSON handler mapping browser.launch to `bridge open` and
// browser.close to `bridge stop`.
func newBridgePluginCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "plugin",
		Short:  "agent-browser provider plugin (exec-once JSON protocol over stdin/stdout).",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBridgePlugin(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

// runBridgePlugin reads the one request envelope from in, validates its protocol,
// dispatches on its type, and writes exactly one JSON response to out. A protocol
// failure emits a success:false envelope and still exits 0; only a stdout write
// failure returns non-nil.
func runBridgePlugin(ctx context.Context, in io.Reader, out io.Writer) error {
	raw, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	var req pluginRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return pluginFail(out, fmt.Errorf("parse plugin request: %w", err))
	}
	if req.Protocol != agentBrowserProtocol {
		return pluginFail(out, fmt.Errorf("unsupported plugin protocol %q", req.Protocol))
	}
	switch req.Type {
	case "plugin.manifest":
		return writePluginJSON(out, pluginManifestResponse{
			Protocol: agentBrowserProtocol,
			Success:  true,
			Manifest: pluginManifest{
				Name:         "cookiesync",
				Capabilities: []string{"browser.provider"},
				Description:  "Seed a throwaway Chrome with your local browser cookies behind one Touch ID tap.",
			},
		})
	case "browser.launch":
		return pluginLaunch(ctx, out, req.Request)
	case "browser.close":
		return pluginClose(ctx, out, req.Request)
	default:
		return pluginFail(out, fmt.Errorf("unsupported plugin request type %q", req.Type))
	}
}

// engineBrowser maps an agent-browser launch engine to the cookiesync browser the
// bridge seeds from; the CDP bridge is Chrome-only.
var engineBrowser = map[string]string{"chrome": "chrome"}

// pluginLaunch maps a browser.launch to a fresh local `bridge open` (default
// profile) and returns its ws:// endpoint as cdpUrl. directPage stays false so
// agent-browser runs its own target discovery and attaches the seeded page.
func pluginLaunch(ctx context.Context, out io.Writer, body json.RawMessage) error {
	var lr pluginLaunchRequest
	if err := json.Unmarshal(body, &lr); err != nil {
		return pluginFail(out, fmt.Errorf("parse browser.launch request: %w", err))
	}
	browser, ok := engineBrowser[lr.LaunchOptions.Engine]
	if !ok {
		return pluginFail(out, fmt.Errorf("unsupported launch engine %q", lr.LaunchOptions.Engine))
	}
	resp, err := openBridge(ctx, "", browser, bridgeDefaultProfile, lr.LaunchOptions.Headed)
	if err != nil {
		return pluginFail(out, err)
	}
	return writePluginJSON(out, pluginLaunchResponse{
		Protocol: agentBrowserProtocol,
		Success:  true,
		Browser: pluginBrowser{
			CDPURL:     resp.URL,
			DirectPage: false,
			Cleanup:    pluginCleanup{Endpoint: bridgeCapKey("", browser, bridgeDefaultProfile)},
		},
	})
}

// pluginClose maps a browser.close to `bridge stop` for the echoed endpoint.
func pluginClose(ctx context.Context, out io.Writer, body json.RawMessage) error {
	var cl pluginCleanup
	if err := json.Unmarshal(body, &cl); err != nil {
		return pluginFail(out, fmt.Errorf("parse browser.close request: %w", err))
	}
	if err := stopBridge(ctx, cl.Endpoint); err != nil {
		return pluginFail(out, err)
	}
	return writePluginJSON(out, pluginOKResponse{Protocol: agentBrowserProtocol, Success: true})
}

// pluginFail emits the success:false envelope carrying cause. A written protocol
// response is a successful run, so it returns nil; only a stdout write failure
// returns non-nil.
func pluginFail(out io.Writer, cause error) error {
	return writePluginJSON(out, pluginErrorResponse{Protocol: agentBrowserProtocol, Success: false, Error: cause.Error()})
}

// writePluginJSON writes v as one compact JSON line — agent-browser reads all of
// the plugin's stdout as a single object.
func writePluginJSON(out io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}
