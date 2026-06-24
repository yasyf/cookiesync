package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// consentReason is the default Touch ID prompt reason for an rpc extract/apply driven
// by a peer over ssh — the frozen wording the Python daemon uses.
const consentReason = "sync them across your Macs"

// extractCookies decrypts every cookie in browser/profile's store with a key obtained
// through consent, returning the count-free decrypted set. It reads the whole store
// (not host-filtered) because a peer syncs the entire profile, not one URL. v20
// app-bound and otherwise-undecryptable rows are dropped. This is the body of the
// frozen "cookiesync rpc extract" contract the ssh peer source depends on.
func extractCookies(ctx context.Context, consent cookie.Consent, browser cookie.Browser, profile string) ([]cookie.Cookie, error) {
	key, err := consent.ObtainKey(ctx, browser, consentReason)
	if err != nil {
		return nil, err
	}
	rows, err := cookie.Read(ctx, browser, profile)
	if err != nil {
		return nil, err
	}
	cookies := make([]cookie.Cookie, 0, len(rows))
	for _, row := range rows {
		if c, ok := cookie.DecryptRow(row, key); ok {
			cookies = append(cookies, c)
		}
	}
	return cookies, nil
}

// applyCookies re-encrypts cookies into browser/profile's live store with a key
// obtained through consent, returning the rows written (-1 on a soft-busy locked
// store). This is the body of the frozen "cookiesync rpc apply" contract.
func applyCookies(ctx context.Context, consent cookie.Consent, browser cookie.Browser, profile string, cookies []cookie.Cookie) (int, error) {
	key, err := consent.ObtainKey(ctx, browser, consentReason)
	if err != nil {
		return 0, err
	}
	return cookie.Apply(ctx, cookies, browser, profile, key)
}

// runRPCExtract resolves the browser, obtains its cookies, and writes the frozen
// {"cookies": [...]} JSON to out.
func runRPCExtract(ctx context.Context, consent cookie.Consent, browserName, profile string, out io.Writer) error {
	browser, err := cookie.Lookup(cookie.BrowserName(browserName))
	if err != nil {
		return err
	}
	cookies, err := extractCookies(ctx, consent, browser, profile)
	if err != nil {
		return err
	}
	payload, err := cookie.MarshalCookies(cookies)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(payload))
	return err
}

// runRPCApply resolves the browser, reads a bare JSON array of wire cookies from in,
// writes them, and emits the frozen {"applied": int} JSON to out.
func runRPCApply(ctx context.Context, consent cookie.Consent, browserName, profile string, in io.Reader, out io.Writer) error {
	browser, err := cookie.Lookup(cookie.BrowserName(browserName))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	cookies, err := cookie.UnmarshalCookies(data)
	if err != nil {
		return fmt.Errorf("parse cookies from stdin: %w", err)
	}
	applied, err := applyCookies(ctx, consent, browser, profile, cookies)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Applied int `json:"applied"`
	}{Applied: applied})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(payload))
	return err
}
