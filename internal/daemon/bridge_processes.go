package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yasyf/daemonkit/durable"

	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/paths"
)

const (
	bridgeProxyLimit       = 8
	bridgeProcessCapacity  = 2 * bridgeProxyLimit
	bridgeRecoverySchemaV1 = 1
	bridgeProcessSuffix    = ".process.json"
)

type bridgeProcessKind string

const (
	bridgeProcessChrome    bridgeProcessKind = "chrome"
	bridgeProcessTunnel    bridgeProcessKind = "tunnel"
	bridgeProcessKeepalive bridgeProcessKind = "keepalive"
)

// bridgeRecoveryMetadata is the sidecar naming one bridge child's product
// liability — what must still be settled if this daemon dies holding it. It is
// published before the child is spawned and lives in the session directory a
// clean close removes wholesale, so exactly the crashed generation's sidecars
// survive into the next start. It carries no process identity: daemonkit
// reclaims the prior generation's children before Prepare runs, so a sidecar
// found at start names a process that is already gone.
type bridgeRecoveryMetadata struct {
	Schema     uint64            `json:"schema"`
	SessionID  string            `json:"session_id"`
	Kind       bridgeProcessKind `json:"kind"`
	Endpoint   string            `json:"endpoint"`
	Host       string            `json:"host,omitempty"`
	Capability string            `json:"capability,omitempty"`

	path string
}

func (m bridgeRecoveryMetadata) validate() error {
	if m.Schema != bridgeRecoverySchemaV1 {
		return fmt.Errorf("bridge: recovery schema %d is not v1", m.Schema)
	}
	if m.SessionID == "" || filepath.Base(m.SessionID) != m.SessionID || m.Endpoint == "" {
		return errors.New("bridge: recovery metadata has invalid session identity")
	}
	switch m.Kind {
	case bridgeProcessChrome, bridgeProcessKeepalive:
		if m.Host != "" || m.Capability != "" {
			return errors.New("bridge: local recovery metadata carries remote authority")
		}
	case bridgeProcessTunnel:
		if m.Host == "" || m.Capability == "" {
			return errors.New("bridge: tunnel recovery metadata lacks remote authority")
		}
	default:
		return fmt.Errorf("bridge: unknown process kind %q", m.Kind)
	}
	return nil
}

type bridgeProcesses struct {
	spawner      bridge.Spawner
	recoveryRoot string
	sessionsRoot string
	rolePath     string
	roleArgs     []string
}

func newBridgeProcesses(rolePath string, spawner bridge.Spawner) (*bridgeProcesses, error) {
	sessionsRoot, err := paths.BridgeSessionsRoot()
	if err != nil {
		return nil, err
	}
	recoveryRoot, err := paths.BridgeRecoveryRoot()
	if err != nil {
		return nil, err
	}
	return &bridgeProcesses{
		spawner: spawner, recoveryRoot: recoveryRoot, sessionsRoot: sessionsRoot, rolePath: rolePath,
	}, nil
}

func (p *bridgeProcesses) sessionDir(sessionID string) string {
	return filepath.Join(p.sessionsRoot, sessionID)
}

func (p *bridgeProcesses) prepareRecoveryRoots() error {
	if err := durable.Mkdir(p.recoveryRoot, 0o700); err != nil {
		return fmt.Errorf("bridge: create recovery root: %w", err)
	}
	if err := durable.Mkdir(p.sessionsRoot, 0o700); err != nil {
		return fmt.Errorf("bridge: create recovery sessions root: %w", err)
	}
	return nil
}

func (p *bridgeProcesses) prepareSessionDir(sessionID string) (string, error) {
	if sessionID == "" || filepath.Base(sessionID) != sessionID {
		return "", errors.New("bridge: invalid recovery session identity")
	}
	if err := p.prepareRecoveryRoots(); err != nil {
		return "", err
	}
	dir := p.sessionDir(sessionID)
	if err := durable.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("bridge: create recovery session: %w", err)
	}
	return dir, nil
}

// record publishes one child's recovery sidecar. It runs before the spawn, so a
// crash between the two leaves a settleable liability rather than an unrecorded
// process.
func (p *bridgeProcesses) record(kind bridgeProcessKind, sessionID, endpoint, host, capability string) error {
	metadata := bridgeRecoveryMetadata{
		Schema: bridgeRecoverySchemaV1, SessionID: sessionID, Kind: kind,
		Endpoint: endpoint, Host: host, Capability: capability,
	}
	if err := metadata.validate(); err != nil {
		return err
	}
	dir, err := p.prepareSessionDir(metadata.SessionID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("bridge: encode recovery metadata: %w", err)
	}
	if err := durable.WriteFile(filepath.Join(dir, bridgeRecoveryFileName(kind)), raw, 0o600); err != nil {
		return fmt.Errorf("bridge: publish recovery metadata: %w", err)
	}
	return nil
}

// settleRecovery discharges every liability the previous generation left
// behind. daemonkit reclaimed that generation's children before Prepare ran, so
// each surviving sidecar names a process that is already gone and a product
// cleanup that never ran.
func (p *bridgeProcesses) settleRecovery(ctx context.Context, runner engine.SSHRunner) error {
	if err := p.prepareRecoveryRoots(); err != nil {
		return err
	}
	metadata, err := p.loadMetadata()
	if err != nil {
		return err
	}
	for _, item := range metadata {
		p.settleProduct(ctx, runner, item)
		if err := p.removeMetadata(item); err != nil {
			return err
		}
	}
	return nil
}

func (p *bridgeProcesses) loadMetadata() ([]bridgeRecoveryMetadata, error) {
	matches, err := filepath.Glob(filepath.Join(p.sessionsRoot, "*", "*"+bridgeProcessSuffix))
	if err != nil {
		return nil, fmt.Errorf("bridge: scan recovery metadata: %w", err)
	}
	items := make([]bridgeRecoveryMetadata, 0, len(matches))
	for _, path := range matches {
		name, ok := parseSidecarName(filepath.Base(path))
		if !ok {
			return nil, fmt.Errorf("bridge: recovery metadata %s is not a sidecar name", path)
		}
		raw, err := os.ReadFile(path) //nolint:gosec // glob is rooted under the exact private recovery root.
		if err != nil {
			return nil, fmt.Errorf("bridge: read recovery metadata: %w", err)
		}
		decode := decodeRecoveryMetadata
		if name.legacy {
			decode = decodeLegacyRecoveryMetadata
		}
		item, err := decode(raw)
		if err != nil {
			return nil, fmt.Errorf("bridge: decode recovery metadata %s: %w", path, err)
		}
		if item.Kind != name.kind || filepath.Dir(path) != p.sessionDir(item.SessionID) {
			return nil, fmt.Errorf("bridge: recovery metadata path %s does not match payload", path)
		}
		item.path = path
		items = append(items, item)
	}
	return items, nil
}

// sidecarName is one sidecar file's name, decomposed. The current format keys on
// kind alone; v0.20 appended a digest of the process-identity tuple, so one
// session could hold several sidecars per kind.
type sidecarName struct {
	kind   bridgeProcessKind
	legacy bool
}

func parseSidecarName(base string) (sidecarName, bool) {
	stem, ok := strings.CutSuffix(base, bridgeProcessSuffix)
	if !ok {
		return sidecarName{}, false
	}
	kind, digest, hyphenated := strings.Cut(stem, "-")
	switch bridgeProcessKind(kind) {
	case bridgeProcessChrome, bridgeProcessTunnel, bridgeProcessKeepalive:
	default:
		return sidecarName{}, false
	}
	if !hyphenated {
		return sidecarName{kind: bridgeProcessKind(kind)}, true
	}
	if len(digest) != hex.EncodedLen(sha256.Size) {
		return sidecarName{}, false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return sidecarName{}, false
	}
	return sidecarName{kind: bridgeProcessKind(kind), legacy: true}, true
}

func decodeRecoveryMetadata(raw []byte) (bridgeRecoveryMetadata, error) {
	var item bridgeRecoveryMetadata
	if err := decodeExact(raw, &item); err != nil {
		return bridgeRecoveryMetadata{}, err
	}
	if err := item.validate(); err != nil {
		return bridgeRecoveryMetadata{}, err
	}
	return item, nil
}

// decodeLegacyRecoveryMetadata reads a v0.20 sidecar. Its payload carried a
// process-identity tuple this version has no use for — daemonkit settles the
// prior generation's children before Prepare runs, so a surviving sidecar is
// matched by nothing but its own presence. Everything the cleanup needs was
// already there, so a legacy sidecar is settled rather than dropped: it can name
// a bridge still open on the peer. Every other unknown field is still refused.
func decodeLegacyRecoveryMetadata(raw []byte) (bridgeRecoveryMetadata, error) {
	var legacy struct {
		Schema     uint64            `json:"schema"`
		SessionID  string            `json:"session_id"`
		Kind       bridgeProcessKind `json:"kind"`
		Process    json.RawMessage   `json:"process"`
		Endpoint   string            `json:"endpoint"`
		Host       string            `json:"host,omitempty"`
		Capability string            `json:"capability,omitempty"`
	}
	if err := decodeExact(raw, &legacy); err != nil {
		return bridgeRecoveryMetadata{}, err
	}
	item := bridgeRecoveryMetadata{
		Schema: legacy.Schema, SessionID: legacy.SessionID, Kind: legacy.Kind,
		Endpoint: legacy.Endpoint, Host: legacy.Host, Capability: legacy.Capability,
	}
	if err := item.validate(); err != nil {
		return bridgeRecoveryMetadata{}, err
	}
	return item, nil
}

func decodeExact(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing content")
	}
	return nil
}

// bridgeRecoveryFileName keys the sidecar on its kind. A session holds at most
// one child of each kind — a local session one chrome, a proxy session one
// tunnel and one keepalive — so kind alone is unique within the session dir.
func bridgeRecoveryFileName(kind bridgeProcessKind) string {
	return string(kind) + bridgeProcessSuffix
}

func (p *bridgeProcesses) settleProduct(ctx context.Context, runner engine.SSHRunner, item bridgeRecoveryMetadata) {
	if item.Kind == bridgeProcessTunnel {
		remoteBridgeClose(ctx, runner, item.Host, item.Capability)
	}
}

// removeMetadata discharges one sidecar. A chrome session owns its whole
// directory, so settling it removes the directory; a proxy session's tunnel and
// keepalive share one, so the last sidecar out removes it.
func (p *bridgeProcesses) removeMetadata(item bridgeRecoveryMetadata) error {
	dir := p.sessionDir(item.SessionID)
	if item.Kind == bridgeProcessChrome {
		return durable.RemoveTree(dir)
	}
	if err := durable.Remove(item.path); err != nil {
		return fmt.Errorf("bridge: remove recovery metadata: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), bridgeProcessSuffix) {
			return nil
		}
	}
	return durable.RemoveTree(dir)
}
