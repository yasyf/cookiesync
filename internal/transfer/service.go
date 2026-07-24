// Package transfer implements CookieSync's exact Synckit snapshot contract.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	dkdaemon "github.com/yasyf/daemonkit/daemon"
	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/syncservice"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

const (
	// Identity is CookieSync's exact v1 transfer schema identity.
	Identity    = "cookiesync-transfer-v1"
	declaration = "payload:{identity:cookiesync-transfer-v1,version:1,browsers:registry};" +
		"delivery:{kind:snapshot|delta,base_revision:uint64,source_revision:uint64,digest:sha256};" +
		"receipt:{origin:string,change_id:sha256,revision:uint64,payload_digest:sha256}"
	ledgerFile = "transfer-v1.json"
	lockFile   = "transfer-v1.lock"
)

// Fingerprint binds the manifest and every delivery to the exact v1 schema.
var Fingerprint = hostregistry.SchemaFingerprint(Identity, declaration)

// RegistryStore owns CookieSync's convergent endpoint registry.
type RegistryStore interface {
	LoadRegistry(context.Context) (cregistry.Registry[state.EndpointMeta], error)
	SaveRegistry(context.Context, cregistry.Registry[state.EndpointMeta]) error
}

// Service exports and applies exact endpoint-registry revisions.
type Service struct {
	Store      RegistryStore
	AfterApply func(context.Context, string) error
}

type payload struct {
	Identity string                                 `json:"identity"`
	Version  uint64                                 `json:"version"`
	Browsers cregistry.Registry[state.EndpointMeta] `json:"browsers"`
}

type receipt struct {
	Origin        string               `json:"origin"`
	ChangeID      string               `json:"change_id"`
	Revision      syncservice.Revision `json:"revision"`
	PayloadDigest string               `json:"payload_digest"`
}

type ledger struct {
	Identity     string    `json:"identity"`
	Version      uint64    `json:"version"`
	Source       uint64    `json:"source_revision"`
	SourceDigest string    `json:"source_payload_digest"`
	Applied      []receipt `json:"applied"`
}

// Export returns the immutable current registry as a full or base-fenced delta.
func (s Service) Export(ctx context.Context, request syncservice.ExportRequest) (syncservice.ChangeEnvelope, error) {
	if s.Store == nil || request.ServiceID != paths.ToolName || request.SchemaFingerprint != Fingerprint {
		return syncservice.ChangeEnvelope{}, errors.New("cookiesync transfer: service schema mismatch")
	}
	since, err := request.SinceRevision.Uint64()
	if err != nil {
		return syncservice.ChangeEnvelope{}, err
	}
	var out syncservice.ChangeEnvelope
	err = withLedger(ctx, func(l *ledger) error {
		registry, err := s.Store.LoadRegistry(ctx)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(payload{Identity: Identity, Version: 1, Browsers: registry})
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		encodedDigest := hex.EncodeToString(digest[:])
		if l.SourceDigest != encodedDigest {
			if l.Source == math.MaxUint64 {
				return errors.New("cookiesync transfer: source revision exhausted")
			}
			l.Source++
			l.SourceDigest = encodedDigest
		}
		if since > l.Source {
			return fmt.Errorf("cookiesync transfer: requested future revision %d, current %d", since, l.Source)
		}
		kind := syncservice.ChangeDelta
		base := syncservice.NewRevision(since)
		if since == 0 {
			kind = syncservice.ChangeSnapshot
			base = syncservice.NewRevision(0)
		}
		out, err = syncservice.NewExportedChange(
			paths.ToolName, Fingerprint, kind, base, syncservice.NewRevision(l.Source), raw,
		)
		return err
	})
	return out, err
}

// Apply merges one exact source registry and acknowledges it after local convergence.
func (s Service) Apply(ctx context.Context, change syncservice.ChangeEnvelope) (syncservice.ApplyResult, error) {
	if s.Store == nil || change.ServiceID != paths.ToolName || change.SchemaFingerprint != Fingerprint {
		return syncservice.ApplyResult{}, errors.New("cookiesync transfer: service schema mismatch")
	}
	if err := change.Validate(true); err != nil {
		return syncservice.ApplyResult{}, err
	}
	var result syncservice.ApplyResult
	err := withLedger(ctx, func(l *ledger) error {
		index := receiptIndex(l.Applied, change.Origin)
		current := syncservice.NewRevision(0)
		if index >= 0 {
			current = l.Applied[index].Revision
			held := l.Applied[index]
			if held.ChangeID == change.ChangeID && held.Revision == change.SourceRevision && held.PayloadDigest == change.PayloadDigest {
				result.AckedRevision = held.Revision
				return nil
			}
		}
		currentNumber, err := current.Uint64()
		if err != nil {
			return err
		}
		sourceNumber, err := change.SourceRevision.Uint64()
		if err != nil {
			return err
		}
		if sourceNumber <= currentNumber {
			return errors.New("cookiesync transfer: stale or conflicting source revision")
		}
		if change.Kind == syncservice.ChangeDelta && change.BaseRevision != current {
			result = syncservice.ApplyResult{AckedRevision: current, NeedSnapshot: true}
			return nil
		}
		incoming, err := decodePayload(change.Payload)
		if err != nil {
			return err
		}
		local, err := s.Store.LoadRegistry(ctx)
		if err != nil {
			return err
		}
		if err := s.Store.SaveRegistry(ctx, cregistry.Merge(local, incoming.Browsers)); err != nil {
			return err
		}
		if s.AfterApply != nil {
			if err := s.AfterApply(ctx, change.Origin); err != nil {
				return err
			}
		}
		next := receipt{
			Origin: change.Origin, ChangeID: change.ChangeID,
			Revision: change.SourceRevision, PayloadDigest: change.PayloadDigest,
		}
		if index < 0 {
			l.Applied = append(l.Applied, next)
		} else {
			l.Applied[index] = next
		}
		result.AckedRevision = change.SourceRevision
		return nil
	})
	return result, err
}

func decodePayload(raw []byte) (payload, error) {
	var decoded payload
	if err := hostregistry.DecodeExactJSON(raw, &decoded); err != nil {
		return payload{}, fmt.Errorf("cookiesync transfer: decode payload: %w", err)
	}
	if decoded.Identity != Identity || decoded.Version != 1 || decoded.Browsers == nil {
		return payload{}, errors.New("cookiesync transfer: payload schema mismatch")
	}
	return decoded, nil
}

func withLedger(ctx context.Context, apply func(*ledger) error) error {
	directory, err := paths.Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	lock, err := (proc.FileLockSpec{
		Path: filepath.Join(directory, lockFile), Mode: proc.FileLockExclusive, Deadline: 30 * time.Second,
	}).Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	path := filepath.Join(directory, ledgerFile)
	l, err := readLedger(path)
	if err != nil {
		return err
	}
	if err := apply(l); err != nil {
		return err
	}
	slices.SortFunc(l.Applied, func(a, b receipt) int { return strings.Compare(a.Origin, b.Origin) })
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return dkdaemon.WriteFileDurable(path, append(raw, '\n'), 0o600)
}

func readLedger(path string) (*ledger, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // fixed private state path
	if errors.Is(err, os.ErrNotExist) {
		return &ledger{Identity: Identity, Version: 1, Applied: []receipt{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var l ledger
	if err := hostregistry.DecodeExactJSON(raw, &l); err != nil {
		return nil, fmt.Errorf("cookiesync transfer: decode ledger: %w", err)
	}
	if l.Identity != Identity || l.Version != 1 || l.Applied == nil {
		return nil, errors.New("cookiesync transfer: ledger schema mismatch")
	}
	if l.Source == 0 && l.SourceDigest != "" || l.Source > 0 && !exactDigest(l.SourceDigest) {
		return nil, errors.New("cookiesync transfer: source ledger is invalid")
	}
	for i, held := range l.Applied {
		if held.Origin == "" || !exactDigest(held.ChangeID) || !exactDigest(held.PayloadDigest) {
			return nil, fmt.Errorf("cookiesync transfer: receipt %d is invalid", i)
		}
		if _, err := held.Revision.Uint64(); err != nil {
			return nil, err
		}
		if receiptIndex(l.Applied[:i], held.Origin) >= 0 {
			return nil, errors.New("cookiesync transfer: duplicate receipt origin")
		}
	}
	return &l, nil
}

func receiptIndex(receipts []receipt, origin string) int {
	for i, held := range receipts {
		if held.Origin == origin {
			return i
		}
	}
	return -1
}

func exactDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
