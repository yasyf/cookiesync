//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"

	synckit "github.com/yasyf/synckit/rpc"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func (d *Daemon) registerPlatform(dispatcher *synckit.Dispatcher) {
	dispatcher.Register("import", d.handleImport)
}

func (d *Daemon) handleImport(ctx context.Context, params map[string]any) (any, error) {
	if _, err := requestorID(ctx, params); err != nil {
		return nil, err
	}
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	if _, err := cookie.Lookup(cookie.BrowserName(browser)); err != nil {
		return nil, err
	}
	profile, err := stringParam(params, "profile")
	if err != nil {
		return nil, err
	}
	if profile == "" {
		return nil, errors.New("import requires a non-empty profile")
	}
	format, err := stringParam(params, "format")
	if err != nil {
		return nil, err
	}
	if format != string(cookie.FormatPlaywright) && format != string(cookie.FormatWebStorage) {
		return nil, fmt.Errorf("unknown import format %q: want playwright or webstorage", format)
	}
	ttlText, err := stringParam(params, "ttl")
	if err != nil {
		return nil, err
	}
	ttl, err := ImportTTL(ttlText)
	if err != nil {
		return nil, err
	}
	hosts, err := hostsParam(params)
	if err != nil {
		return nil, err
	}
	document, err := stringParam(params, "document")
	if err != nil {
		return nil, err
	}
	parsed, err := cookie.ParseRendered([]byte(document), cookie.OutputFormat(format))
	if err != nil {
		return nil, err
	}
	rec, err := newImportRecord(hosts, parsed, d.now().Add(ttl).Round(0))
	if err != nil {
		return nil, err
	}
	if err := d.imports.hold(importKey{browser: browser, profile: profile}, rec); err != nil {
		return nil, err
	}
	return map[string]any{
		"protocol_version": cookie.ProtocolVersion,
		"browser":          browser,
		"profile":          profile,
		"hosts":            rec.hostList(),
		"cookies":          len(rec.cookies),
		"origins":          len(rec.origins),
		"expires_in":       ttl.Seconds(),
	}, nil
}

func hostsParam(params map[string]any) ([]string, error) {
	raw, ok := params["hosts"].([]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("import requires non-empty hosts")
	}
	hosts := make([]string, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("hosts[%d] is %T, want non-empty string", i, v)
		}
		hosts[i] = s
	}
	return hosts, nil
}
