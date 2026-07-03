package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/hostregistry"
)

// newNonce mints a fresh routed-consent nonce: URL-safe base64 of 24 random bytes,
// matching the shape of the Python secrets.token_urlsafe(32) (which also encodes 24
// bytes, since token_urlsafe's argument is the byte count, not the char count). A
// fresh nonce per release binds each approval to exactly one request.
func newNonce() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate consent nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// routedRelease routes the user-presence gate to the active peer, then releases this
// host's own key non-interactively. The peer's request_consent reply must echo the
// exact nonce and endpoint this host sent; otherwise the approval is unbound and we
// fail closed with AuthRequired — a mismatch is a security failure, never a retry.
// Only after that verified approval do we read this host's own key (via
// ObtainKeyUnprompted) — it never crosses the wire. Mirrors the Python routed_release.
func (d *Daemon) routedRelease(ctx context.Context, browser cookie.Browser, browserID, profile string) (cookie.AesKey, error) {
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	peer, err := d.activePeer(ctx, st)
	if err != nil {
		return nil, err
	}
	nonce, err := d.newNonce()
	if err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := endpointID(self, browserID, profile)
	cmd := fmt.Sprintf(
		"cookiesync rpc request_consent --browser %s --profile %s --nonce %s --endpoint %s",
		hostregistry.ShellQuote(browserID), hostregistry.ShellQuote(profile),
		hostregistry.ShellQuote(nonce), hostregistry.ShellQuote(endpoint),
	)
	out, err := d.runner.Run(ctx, peer, cmd, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Status   string `json:"status"`
		Nonce    string `json:"nonce"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("parse request_consent from %s: %w", peer, err)
	}
	if resp.Status != "approved" || resp.Nonce != nonce || resp.Endpoint != endpoint {
		return nil, &AuthRequired{Msg: fmt.Sprintf("consent %s from %s", statusOrUnavailable(resp.Status), peer)}
	}
	return d.consent.ObtainKeyUnprompted(ctx, browser)
}

// activePeer finds the peer whose live, unlocked session can approve consent. A set
// consent_route_to that is live short-circuits the scan; otherwise every peer in
// reposync's host mesh is probed and the first live one wins. The candidate peers come
// from reposync, not this host's tracked endpoints, so a freshly-installed host with no
// peer endpoints can still route consent to a live peer. No live peer is AuthRequired.
// Mirrors the Python active_peer.
func (d *Daemon) activePeer(ctx context.Context, st *state.State) (string, error) {
	if st.ConsentRouteTo != "" {
		live, err := d.peerIsLive(ctx, st.ConsentRouteTo)
		if err != nil {
			return "", err
		}
		if live {
			return st.ConsentRouteTo, nil
		}
	}
	_, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return "", err
	}
	for _, peer := range peers {
		live, err := d.peerIsLive(ctx, peer)
		if err != nil {
			return "", err
		}
		if live {
			return peer, nil
		}
	}
	return "", &AuthRequired{Msg: "no peer has a live session to approve consent"}
}

// peerIsLive reports whether peer has a live, unlocked, un-shared console session, read
// over ssh via its whoami RPC: on_console && !locked && !screen_shared. A screen-shared
// peer is not a valid approver — its Touch ID prompt may be tapped by the remote viewer
// rather than the physically-present human — so it is skipped. Mirrors the Python
// peer_is_live.
func (d *Daemon) peerIsLive(ctx context.Context, peer string) (bool, error) {
	out, err := d.runner.Run(ctx, peer, "cookiesync rpc whoami", nil)
	if err != nil {
		return false, err
	}
	var summary struct {
		OnConsole    bool `json:"on_console"`
		Locked       bool `json:"locked"`
		ScreenShared bool `json:"screen_shared"`
	}
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		return false, fmt.Errorf("parse whoami from %s: %w", peer, err)
	}
	return summary.OnConsole && !summary.Locked && !summary.ScreenShared, nil
}

// handleRequestConsent shows the Touch ID prompt to the person at this machine for the
// requesting endpoint and echoes the requester's nonce + endpoint VERBATIM to bind the
// approval — no key crosses the wire. The approval runs the approver-mode prime for
// the requested browser+profile on behalf of the requesting endpoint's host, so the
// same tap warms this host's own cache and grants that host a consent window — a
// repeat routed request inside it is approved silently; the approver's own endpoint
// ids are cache keys only, never in the reply. Returns {"status": "approved",
// "nonce", "endpoint"} on a live tap, {"status": "denied"} when declined, or
// {"status": "unavailable"} when this host has no live session to prompt or its
// keybag is locked. Mirrors the Python request_consent.
func (d *Daemon) handleRequestConsent(ctx context.Context, params map[string]any) (any, error) {
	browserID, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	nonce, err := stringParam(params, "nonce")
	if err != nil {
		return nil, err
	}
	endpoint, err := stringParam(params, "endpoint")
	if err != nil {
		return nil, err
	}
	live, err := HasActiveSession(ctx, d.probe)
	if err != nil {
		return nil, err
	}
	if !live {
		return map[string]any{"status": "unavailable"}, nil
	}
	host, _, _ := strings.Cut(endpoint, ":")
	if _, _, err := d.primeAuth(ctx, "host:"+host, browserID, profile, fmt.Sprintf("sync them to %s", endpoint), releaseApprover); err != nil {
		var authErr *AuthRequired
		if errors.Is(err, cookie.ErrKeybagLocked) || errors.As(err, &authErr) {
			return map[string]any{"status": "unavailable"}, nil
		}
		var declined *cookie.ConsentError
		if errors.As(err, &declined) {
			return map[string]any{"status": "denied"}, nil
		}
		return nil, err
	}
	return map[string]any{"status": "approved", "nonce": nonce, "endpoint": endpoint}, nil
}

// statusOrUnavailable echoes the peer's reported status, defaulting to "unavailable"
// when the reply omitted it — matching the Python `resp.get('status') or 'unavailable'`.
func statusOrUnavailable(status string) string {
	if status == "" {
		return "unavailable"
	}
	return status
}
