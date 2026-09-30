package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	synckit "github.com/yasyf/synckit/rpc"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/daemon"
)

func newImportCmd() *cobra.Command {
	var format, ttl, browser, profile string
	cmd := &cobra.Command{
		Use:   "import --format <playwright|webstorage> --ttl <duration> --browser <browser> --profile <profile> -- <host>...",
		Short: "Hold a cookies document piped from a Mac in the helper's memory for the named hosts until --ttl lapses.",
		Long: "Read exactly one JSON document from stdin, the output of `cookiesync cookies --browser B --profile P " +
			"--format playwright|webstorage -- HOST...` run on a Mac, and hold it in the resident helper's memory for " +
			"--ttl, bound to --browser, --profile and the named hosts. Nothing is written to disk. A helper restart or " +
			"the ttl lapsing drops it, and a new import for the same browser and profile replaces it.\n\n" +
			"While it lives, `cookies` (with or without --browser) and `bridge open` serve it instead of the local " +
			"store whenever every requested host is a named host; any other request takes the normal path. The " +
			"import is refused whole when a cookie or origin reaches past the named hosts. Playwright documents " +
			"carry cookies and localStorage; webstorage documents carry localStorage and sessionStorage and no cookies.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, hosts []string) error {
			return runImport(cmd, hosts, format, ttl, browser, profile)
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "The document's format: playwright or webstorage.")
	cmd.Flags().StringVar(&ttl, "ttl", "", "How long the helper holds the document, 1s..24h (e.g. 1h).")
	cmd.Flags().StringVar(&browser, "browser", "", "The browser the document was exported from and is served as.")
	cmd.Flags().StringVar(&profile, "profile", "", "The profile the document was exported from and is served as.")
	_ = cmd.MarkFlagRequired("format")
	_ = cmd.MarkFlagRequired("ttl")
	_ = cmd.MarkFlagRequired("browser")
	_ = cmd.MarkFlagRequired("profile")
	return cmd
}

func runImport(cmd *cobra.Command, hosts []string, format, ttl, browser, profile string) error {
	switch cookie.OutputFormat(format) {
	case cookie.FormatPlaywright, cookie.FormatWebStorage:
	default:
		return fmt.Errorf("unknown import format %q: want playwright or webstorage", format)
	}
	if _, err := daemon.ImportTTL(ttl); err != nil {
		return err
	}
	if browser == "" {
		return errors.New("--browser must not be empty")
	}
	if profile == "" {
		return errors.New("--profile must not be empty")
	}
	document, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), synckit.MaxPayload+1))
	if err != nil {
		return fmt.Errorf("read import document from stdin: %w", err)
	}
	params := map[string]any{
		"browser": browser, "profile": profile, "format": format, "ttl": ttl,
		"hosts": asAnySlice(hosts), "document": string(document),
	}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
	}
	body, err := synckit.EncodeRequest(&synckit.Request{Method: "import", Params: params})
	if err != nil {
		return err
	}
	if len(body) > synckit.MaxPayload {
		return fmt.Errorf("import request exceeds the %d-byte RPC payload limit (synckit rpc.MaxPayload)", synckit.MaxPayload)
	}
	result, err := rpcCall(cmd.Context(), "import", params)
	if err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("re-encode import result: %w", err)
	}
	var reply struct {
		ProtocolVersion uint64   `json:"protocol_version"`
		Browser         string   `json:"browser"`
		Profile         string   `json:"profile"`
		Hosts           []string `json:"hosts"`
		Cookies         int      `json:"cookies"`
		Origins         int      `json:"origins"`
		ExpiresIn       float64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return fmt.Errorf("decode import result: %w", err)
	}
	if reply.ProtocolVersion != cookie.ProtocolVersion {
		return fmt.Errorf("cookie protocol version %d, want %d", reply.ProtocolVersion, cookie.ProtocolVersion)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "imported %d cookie(s) and %d origin(s) into %s/%s for %s (expires in %s)\n",
		reply.Cookies, reply.Origins, reply.Browser, reply.Profile, strings.Join(reply.Hosts, ", "), formatTTL(reply.ExpiresIn))
	return err
}
