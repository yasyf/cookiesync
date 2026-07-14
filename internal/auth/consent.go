package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/rpc"
)

// sshConnFailureExit is ssh's own connection-failure exit status — the only
// exit code the routed-consent failover treats as a transport failure.
const sshConnFailureExit = 255

// consentTimeout bounds the request_consent ssh leg, which may block on a
// routed human consent — a Touch ID tap on the peer. Derived from the peer
// handler's own rpc.DispatchTimeout: the human keeps nearly that full window,
// and the 30s margin makes us give up just before the peer's deadline fires.
// A var so tests shrink it.
var consentTimeout = rpc.DispatchTimeout - 30*time.Second

// probeLiveTimeout bounds one peer's whoami liveness probe: a data-plane read
// that must fail in seconds, never ride a release flight's consent-window
// deadline. A var so tests shrink it.
var probeLiveTimeout = 10 * time.Second

// newNonce mints a fresh routed-consent nonce: URL-safe base64 of 24 random
// bytes, matching the shape of the Python secrets.token_urlsafe(32) (which also
// encodes 24 bytes, since token_urlsafe's argument is the byte count, not the
// char count). A fresh nonce per release binds each approval to exactly one
// request.
func newNonce() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate consent nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// routedRelease routes the user-presence gate across the approver candidates —
// a set consent_route_to first, then every mesh peer — and releases this host's
// own key non-interactively after the first bound approval. A peer that is not
// live, timed out, failed at the ssh transport (exit-255), or answered an
// explicit unavailable is routed around: the next candidate is tried. Any other
// failure — a whoami or consent reply that does not parse, an unexpected status,
// a remote command's real exit — propagates fatally rather than masquerading as
// peer-offline. A denial is terminal — a human said no, and no other peer
// is ever asked — and an approval that fails to echo the exact nonce and
// endpoint this host sent fails closed with AuthRequired: a mismatch is a
// security failure, never a retry. Each attempt binds its own fresh nonce. Only
// after a verified approval do we read this host's own key (via
// ObtainKeyUnprompted) — it never crosses the wire. Candidates exhausted is
// AuthRequired.
func (b *Broker) routedRelease(ctx context.Context, browser cookie.Browser, browserID, profile string) (cookie.AesKey, error) {
	st, err := b.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	self, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := endpointID(self, browserID, profile)
	candidates := make([]string, 0, len(peers)+1)
	if st.ConsentRouteTo != "" {
		candidates = append(candidates, st.ConsentRouteTo)
	}
	for _, peer := range peers {
		if peer != st.ConsentRouteTo {
			candidates = append(candidates, peer)
		}
	}
	var lastErr error
	for _, peer := range candidates {
		live, err := b.peerIsLive(ctx, peer)
		if err != nil && !routesAround(err) {
			return nil, err
		}
		if err != nil || !live {
			continue
		}
		key, next, err := b.requestConsent(ctx, peer, browser, browserID, profile, endpoint)
		if !next {
			return key, err
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &AuthRequired{Msg: "no peer has a live session to approve consent"}
}

// requestConsent runs one routed-consent attempt against peer, minting a fresh
// nonce for it. next reports whether routedRelease should advance to another
// approver — the ssh leg failed at the transport (routesAround), or the peer
// answered an explicit unavailable; next false carries the terminal outcome:
// the released key, a denial, an unbound approval's AuthRequired, or a fatal
// protocol failure (an unparseable reply or an unexpected status).
func (b *Broker) requestConsent(ctx context.Context, peer string, browser cookie.Browser, browserID, profile, endpoint string) (key cookie.AesKey, next bool, err error) {
	nonce, err := b.Nonce()
	if err != nil {
		return nil, false, err
	}
	cmd := fmt.Sprintf(
		"cookiesync rpc request_consent --browser %s --profile %s --nonce %s --endpoint %s",
		hostregistry.ShellQuote(browserID), hostregistry.ShellQuote(profile),
		hostregistry.ShellQuote(nonce), hostregistry.ShellQuote(endpoint),
	)
	cctx, cancel := context.WithTimeout(ctx, consentTimeout)
	defer cancel()
	out, err := b.runner.Run(cctx, peer, cmd, nil)
	if err != nil {
		if routesAround(err) {
			return nil, true, &AuthRequired{Msg: fmt.Sprintf("consent unreachable at %s: %v", peer, err)}
		}
		return nil, false, fmt.Errorf("request_consent to %s: %w", peer, err)
	}
	var resp struct {
		Status   string `json:"status"`
		Nonce    string `json:"nonce"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, false, fmt.Errorf("parse request_consent from %s: %w", peer, err)
	}
	switch resp.Status {
	case "denied":
		return nil, false, &AuthRequired{Msg: fmt.Sprintf("consent denied from %s", peer)}
	case "unavailable":
		return nil, true, &AuthRequired{Msg: fmt.Sprintf("consent unavailable from %s", peer)}
	case "approved":
	default:
		return nil, false, fmt.Errorf("request_consent from %s answered unexpected status %q", peer, resp.Status)
	}
	if resp.Nonce != nonce || resp.Endpoint != endpoint {
		return nil, false, &AuthRequired{Msg: fmt.Sprintf("consent approved from %s did not echo this request's nonce and endpoint", peer)}
	}
	key, err = b.consent.ObtainKeyUnprompted(ctx, browser)
	return key, false, err
}

// peerIsLive reports whether peer has a live, unlocked, un-shared console
// session, read over ssh via its whoami RPC under probeLiveTimeout:
// on_console && !locked && !screen_shared. A screen-shared peer is not a valid
// approver — its Touch ID prompt may be tapped by the remote viewer rather than
// the physically-present human — so it is skipped.
func (b *Broker) peerIsLive(ctx context.Context, peer string) (bool, error) {
	pctx, cancel := context.WithTimeout(ctx, probeLiveTimeout)
	defer cancel()
	out, err := b.runner.Run(pctx, peer, "cookiesync rpc whoami", nil)
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

// routesAround reports whether a probe or consent-leg failure is a genuine
// transport failure the routed-consent failover may route around: a timed-out
// leg, or an *hostregistry.SSHError caused by ssh's own exit-255 connection
// failure. Anything else is a protocol failure the caller propagates.
func routesAround(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var sshErr *hostregistry.SSHError
	if !errors.As(err, &sshErr) {
		return false
	}
	var exitErr *exec.ExitError
	return errors.As(sshErr.Err, &exitErr) && exitErr.ExitCode() == sshConnFailureExit
}
