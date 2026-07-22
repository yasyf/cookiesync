package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/supervise"

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

type bridgeRecoveryMetadata struct {
	Schema     uint64            `json:"schema"`
	SessionID  string            `json:"session_id"`
	Kind       bridgeProcessKind `json:"kind"`
	Record     proc.Record       `json:"record"`
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
	if err := m.Record.Validate(); err != nil {
		return err
	}
	if m.Record.RecoveryClass != proc.RecoveryTask {
		return errors.New("bridge: recovery record has wrong class")
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
	pool         *supervise.Pool
	reaper       *proc.Reaper
	recoveryRoot string
	sessionsRoot string
	rolePath     string
	roleArgs     []string
	syncDir      func(string) error
}

func newBridgeProcesses(rolePath string) (*bridgeProcesses, error) {
	generation, err := proc.ProcessGeneration()
	if err != nil {
		return nil, err
	}
	return newBridgeProcessesGeneration(rolePath, generation)
}

func newBridgeProcessesGeneration(rolePath, generation string) (*bridgeProcesses, error) {
	storePath, err := paths.BridgeProcessStorePath()
	if err != nil {
		return nil, err
	}
	sessionsRoot, err := paths.BridgeSessionsRoot()
	if err != nil {
		return nil, err
	}
	recoveryRoot, err := paths.BridgeRecoveryRoot()
	if err != nil {
		return nil, err
	}
	reaper := &proc.Reaper{
		Store:      &proc.FileStore{Path: storePath, MaxOutstanding: 4 * bridgeProcessCapacity},
		Generation: generation,
		Grace:      supervise.TerminationGrace,
	}
	pool, err := supervise.NewPool(bridgeProcessCapacity, reaper)
	if err != nil {
		return nil, err
	}
	return &bridgeProcesses{
		pool: pool, reaper: reaper, recoveryRoot: recoveryRoot, sessionsRoot: sessionsRoot,
		rolePath: rolePath, syncDir: syncDirectory,
	}, nil
}

func (p *bridgeProcesses) Close() { p.pool.Close() }

func (p *bridgeProcesses) Cancel() { p.pool.Cancel() }

func (p *bridgeProcesses) Wait(ctx context.Context) error { return p.pool.Wait(ctx) }

func (p *bridgeProcesses) sessionDir(sessionID string) string {
	return filepath.Join(p.sessionsRoot, sessionID)
}

func (p *bridgeProcesses) prepareRecoveryRoots() error {
	if err := os.MkdirAll(p.recoveryRoot, 0o700); err != nil {
		return fmt.Errorf("bridge: create recovery root: %w", err)
	}
	if err := p.syncDir(filepath.Dir(p.recoveryRoot)); err != nil {
		return fmt.Errorf("bridge: commit recovery root: %w", err)
	}
	if err := os.MkdirAll(p.sessionsRoot, 0o700); err != nil {
		return fmt.Errorf("bridge: create recovery sessions root: %w", err)
	}
	if err := p.syncDir(p.recoveryRoot); err != nil {
		return fmt.Errorf("bridge: commit recovery sessions root: %w", err)
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("bridge: create recovery session: %w", err)
	}
	if err := p.syncDir(p.sessionsRoot); err != nil {
		return "", fmt.Errorf("bridge: commit recovery session: %w", err)
	}
	return dir, nil
}

func (p *bridgeProcesses) recorded(
	kind bridgeProcessKind,
	sessionID, endpoint, host, capability string,
) func(context.Context, proc.Record) error {
	return func(ctx context.Context, record proc.Record) error {
		metadata := bridgeRecoveryMetadata{
			Schema: bridgeRecoverySchemaV1, SessionID: sessionID, Kind: kind,
			Record: record, Endpoint: endpoint, Host: host, Capability: capability,
		}
		return p.writeMetadata(ctx, metadata)
	}
}

func (p *bridgeProcesses) writeMetadata(ctx context.Context, metadata bridgeRecoveryMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
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
	name, err := bridgeRecoveryFileName(metadata.Kind, metadata.Record)
	if err != nil {
		return err
	}
	final := filepath.Join(dir, name)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // fixed file below the private session root.
	if err != nil {
		return fmt.Errorf("bridge: create recovery metadata: %w", err)
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("bridge: persist recovery metadata: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("bridge: commit recovery metadata: %w", err)
	}
	return p.syncDir(dir)
}

func (p *bridgeProcesses) reap(ctx context.Context) error {
	if err := p.prepareRecoveryRoots(); err != nil {
		return err
	}
	return p.pool.Recover(ctx)
}

func (p *bridgeProcesses) settleRecovery(ctx context.Context, runner engine.SSHRunner) error {
	if err := p.removeUncommittedMetadata(); err != nil {
		return err
	}
	metadata, err := p.loadMetadata()
	if err != nil {
		return err
	}
	byRecord := make(map[proc.Record]bridgeRecoveryMetadata, len(metadata))
	for _, item := range metadata {
		byRecord[item.Record] = item
	}
	var cursor proc.ReapReceiptCursor
	for {
		page, err := p.reaper.ReapReceipts(ctx, proc.RecoveryTask, cursor, proc.ReapReceiptPageLimit)
		if err != nil {
			return err
		}
		for _, receipt := range page.Receipts {
			item, ok := byRecord[receipt.Record]
			if ok {
				p.settleProduct(ctx, runner, item)
				if err := p.removeMetadata(item); err != nil {
					return err
				}
				delete(byRecord, receipt.Record)
			}
			if _, err := p.reaper.AcknowledgeReap(ctx, receipt); err != nil {
				return err
			}
			cursor = proc.ReapReceiptCursor{LedgerID: receipt.LedgerID, Sequence: receipt.Sequence}
		}
		if !page.More {
			break
		}
	}
	active, err := p.reaper.Store.Load(ctx)
	if err != nil {
		return err
	}
	for _, item := range byRecord {
		if slices.Contains(active, item.Record) {
			continue
		}
		p.settleProduct(ctx, runner, item)
		if err := p.removeMetadata(item); err != nil {
			return err
		}
	}
	return nil
}

func (p *bridgeProcesses) recover(ctx context.Context, runner engine.SSHRunner) error {
	if err := p.reap(ctx); err != nil {
		return err
	}
	return p.settleRecovery(ctx, runner)
}

func (p *bridgeProcesses) removeUncommittedMetadata() error {
	matches, err := filepath.Glob(filepath.Join(p.sessionsRoot, "*", "*"+bridgeProcessSuffix+".tmp"))
	if err != nil {
		return fmt.Errorf("bridge: scan uncommitted recovery metadata: %w", err)
	}
	for _, path := range matches {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("bridge: remove uncommitted recovery metadata: %w", err)
		}
		if err := p.syncDir(filepath.Dir(path)); err != nil {
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
		raw, err := os.ReadFile(path) //nolint:gosec // glob is rooted under the exact private recovery root.
		if err != nil {
			return nil, fmt.Errorf("bridge: read recovery metadata: %w", err)
		}
		var item bridgeRecoveryMetadata
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&item); err != nil {
			return nil, fmt.Errorf("bridge: decode recovery metadata %s: %w", path, err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("bridge: recovery metadata %s has trailing content", path)
		}
		if err := item.validate(); err != nil {
			return nil, fmt.Errorf("bridge: validate recovery metadata %s: %w", path, err)
		}
		name, err := bridgeRecoveryFileName(item.Kind, item.Record)
		if err != nil {
			return nil, err
		}
		if want := filepath.Join(p.sessionDir(item.SessionID), name); path != want {
			return nil, fmt.Errorf("bridge: recovery metadata path %s does not match payload", path)
		}
		item.path = path
		items = append(items, item)
	}
	return items, nil
}

func bridgeRecoveryFileName(kind bridgeProcessKind, record proc.Record) (string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("bridge: encode recovery record identity: %w", err)
	}
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("%s-%x%s", kind, digest, bridgeProcessSuffix), nil
}

func (p *bridgeProcesses) settleProduct(ctx context.Context, runner engine.SSHRunner, item bridgeRecoveryMetadata) {
	if item.Kind == bridgeProcessTunnel {
		remoteBridgeClose(ctx, runner, item.Host, item.Capability)
	}
}

func (p *bridgeProcesses) removeMetadata(item bridgeRecoveryMetadata) error {
	dir := p.sessionDir(item.SessionID)
	if item.Kind == bridgeProcessChrome {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("bridge: remove recovery session: %w", err)
		}
		return p.syncDir(p.sessionsRoot)
	}
	if err := os.Remove(item.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bridge: remove recovery metadata: %w", err)
	}
	if err := p.syncDir(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
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
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("bridge: remove recovery session: %w", err)
	}
	return p.syncDir(p.sessionsRoot)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path) //nolint:gosec // internal exact recovery path.
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
