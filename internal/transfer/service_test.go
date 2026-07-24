package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/syncservice"
)

type memoryStore struct {
	registry cregistry.Registry[state.EndpointMeta]
	saves    int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{registry: cregistry.New[state.EndpointMeta]()}
}

func (s *memoryStore) LoadRegistry(context.Context) (cregistry.Registry[state.EndpointMeta], error) {
	return cregistry.Merge(cregistry.New[state.EndpointMeta](), s.registry), nil
}

func (s *memoryStore) SaveRegistry(_ context.Context, registry cregistry.Registry[state.EndpointMeta]) error {
	s.registry = cregistry.Merge(cregistry.New[state.EndpointMeta](), registry)
	s.saves++
	return nil
}

func initialize(t *testing.T) {
	t.Helper()
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
}

func exportRequest(revision uint64) syncservice.ExportRequest {
	return syncservice.ExportRequest{
		ServiceID: paths.ToolName, SchemaFingerprint: Fingerprint,
		SinceRevision: syncservice.NewRevision(revision),
	}
}

func boundChange(t *testing.T, kind syncservice.ChangeKind, base, source uint64, registry cregistry.Registry[state.EndpointMeta]) syncservice.ChangeEnvelope {
	t.Helper()
	raw, err := json.Marshal(payload{Identity: Identity, Version: 1, Browsers: registry})
	if err != nil {
		t.Fatal(err)
	}
	change, err := syncservice.NewExportedChange(
		paths.ToolName, Fingerprint, kind,
		syncservice.NewRevision(base), syncservice.NewRevision(source), raw,
	)
	if err != nil {
		t.Fatal(err)
	}
	change, err = syncservice.BindDelivery(change, "source@example")
	if err != nil {
		t.Fatal(err)
	}
	return change
}

func TestExportAdvancesOnlyWhenRegistryChanges(t *testing.T) {
	initialize(t)
	store := newMemoryStore()
	service := Service{Store: store}

	first, err := service.Export(t.Context(), exportRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	if first.Kind != syncservice.ChangeSnapshot || first.BaseRevision != "0" || first.SourceRevision != "1" {
		t.Fatalf("initial change = %+v", first)
	}
	unchanged, err := service.Export(t.Context(), exportRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Kind != syncservice.ChangeDelta || unchanged.BaseRevision != "1" || unchanged.SourceRevision != "1" {
		t.Fatalf("unchanged change = %+v", unchanged)
	}
	store.registry.Add("desktop:chrome:Default", state.EndpointMeta{
		Host: "desktop", Browser: "chrome", Profile: "Default",
	}, cregistry.UnixMicros(time.Unix(1, 0)))
	changed, err := service.Export(t.Context(), exportRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	if changed.Kind != syncservice.ChangeDelta || changed.BaseRevision != "1" || changed.SourceRevision != "2" {
		t.Fatalf("changed change = %+v", changed)
	}
}

func TestApplyIsExactlyIdempotentAndBaseFenced(t *testing.T) {
	initialize(t)
	store := newMemoryStore()
	after := 0
	service := Service{Store: store, AfterApply: func(context.Context, string) error {
		after++
		return nil
	}}
	incoming := cregistry.New[state.EndpointMeta]()
	incoming.Add("source:chrome:Default", state.EndpointMeta{
		Host: "source", Browser: "chrome", Profile: "Default",
	}, cregistry.UnixMicros(time.Unix(1, 0)))
	snapshot := boundChange(t, syncservice.ChangeSnapshot, 0, 1, incoming)

	ack, err := service.Apply(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if ack.NeedSnapshot || ack.AckedRevision != "1" || store.saves != 1 || after != 1 {
		t.Fatalf("first apply = %+v saves=%d after=%d", ack, store.saves, after)
	}
	replay, err := service.Apply(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if replay != ack || store.saves != 1 || after != 1 {
		t.Fatalf("replay = %+v saves=%d after=%d", replay, store.saves, after)
	}

	mismatch, err := service.Apply(t.Context(), boundChange(t, syncservice.ChangeDelta, 0, 2, incoming))
	if err != nil {
		t.Fatal(err)
	}
	if !mismatch.NeedSnapshot || mismatch.AckedRevision != "1" || store.saves != 1 || after != 1 {
		t.Fatalf("mismatch = %+v saves=%d after=%d", mismatch, store.saves, after)
	}
}

func TestApplyRecordsReceiptOnlyAfterConvergence(t *testing.T) {
	initialize(t)
	store := newMemoryStore()
	want := errors.New("convergence failed")
	fail := true
	calls := 0
	service := Service{Store: store, AfterApply: func(context.Context, string) error {
		calls++
		if fail {
			return want
		}
		return nil
	}}
	change := boundChange(t, syncservice.ChangeSnapshot, 0, 1, cregistry.New[state.EndpointMeta]())
	if _, err := service.Apply(t.Context(), change); !errors.Is(err, want) {
		t.Fatalf("first apply error = %v", err)
	}
	fail = false
	ack, err := service.Apply(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	if ack.AckedRevision != "1" || calls != 2 {
		t.Fatalf("retry = %+v calls=%d", ack, calls)
	}
}

func TestTransferRejectsForeignSchemaBeforeUse(t *testing.T) {
	initialize(t)
	service := Service{Store: newMemoryStore()}
	request := exportRequest(0)
	request.SchemaFingerprint = "foreign"
	if _, err := service.Export(t.Context(), request); err == nil {
		t.Fatal("foreign export schema accepted")
	}
	change := boundChange(t, syncservice.ChangeSnapshot, 0, 1, cregistry.New[state.EndpointMeta]())
	change.SchemaFingerprint = "foreign"
	if _, err := service.Apply(t.Context(), change); err == nil {
		t.Fatal("foreign apply schema accepted")
	}
}
