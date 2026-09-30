//go:build linux

package cookie

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/godbus/dbus/v5"
)

const (
	fakeSecret            = "synthetic-safe-storage-secret"        //nolint:gosec // G101: synthetic test secret.
	fakeStaleSecret       = "stale-secret-from-another-collection" //nolint:gosec // G101: synthetic test secret.
	fakeDefaultCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	fakeOtherCollection   = dbus.ObjectPath("/org/freedesktop/secrets/collection/session")
	fakeItemPath          = fakeDefaultCollection + "/1"
	fakeOtherItemPath     = fakeOtherCollection + "/1"
	fakeSession           = dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	fakePrompt            = dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")
)

// fakeSecretService scripts one Secret Service holding named collections and
// records every call it received, in order.
type fakeSecretService struct {
	calls       []string
	alias       dbus.ObjectPath
	aliasErr    error
	collections map[dbus.ObjectPath]*fakeCollection
	unlockErr   error
	prompt      dbus.ObjectPath
	sessionErr  error
	searchErr   error
	secretErr   error
	searched    dbus.ObjectPath
	attributes  map[string]string
	closed      bool
}

type fakeCollection struct {
	locked bool
	items  map[dbus.ObjectPath]fakeItem
}

type fakeItem struct {
	application string
	secret      []byte
}

// unlockedDefault is a service whose "default" alias names an unlocked
// collection holding items, and no other collection.
func unlockedDefault(items map[dbus.ObjectPath]fakeItem) *fakeSecretService {
	return &fakeSecretService{
		alias:       fakeDefaultCollection,
		prompt:      noPromptPath,
		collections: map[dbus.ObjectPath]*fakeCollection{fakeDefaultCollection: {items: items}},
	}
}

// lockedDefault is unlockedDefault with the default collection locked; prompt is
// what Unlock answers, noPromptPath unlocking it in place.
func lockedDefault(prompt dbus.ObjectPath, items map[dbus.ObjectPath]fakeItem) *fakeSecretService {
	f := unlockedDefault(items)
	f.collections[fakeDefaultCollection].locked = true
	f.prompt = prompt
	return f
}

// withOther adds an unlocked non-default collection holding items.
func (f *fakeSecretService) withOther(items map[dbus.ObjectPath]fakeItem) *fakeSecretService {
	if f.collections == nil {
		f.collections = map[dbus.ObjectPath]*fakeCollection{}
	}
	f.collections[fakeOtherCollection] = &fakeCollection{items: items}
	return f
}

func chromeItem(path dbus.ObjectPath, secret string) map[dbus.ObjectPath]fakeItem {
	return map[dbus.ObjectPath]fakeItem{path: {application: "chrome", secret: []byte(secret)}}
}

func (f *fakeSecretService) readAlias(_ context.Context, name string) (dbus.ObjectPath, error) {
	f.calls = append(f.calls, "readAlias")
	if name != defaultCollectionAlias {
		return "", errors.New("readAlias asked for an alias other than default")
	}
	return f.alias, f.aliasErr
}

func (f *fakeSecretService) unlock(_ context.Context, objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, error) {
	f.calls = append(f.calls, "unlock")
	if f.unlockErr != nil {
		return nil, "", f.unlockErr
	}
	unlocked := make([]dbus.ObjectPath, 0, len(objects))
	for _, object := range objects {
		c, ok := f.collections[object]
		if !ok {
			return nil, "", errors.New("unlock asked for a collection the fake never advertised")
		}
		if c.locked {
			if f.prompt != noPromptPath {
				return nil, f.prompt, nil
			}
			c.locked = false
		}
		unlocked = append(unlocked, object)
	}
	return unlocked, noPromptPath, nil
}

func (f *fakeSecretService) openSession(context.Context) (dbus.ObjectPath, error) {
	f.calls = append(f.calls, "openSession")
	return fakeSession, f.sessionErr
}

func (f *fakeSecretService) searchItems(_ context.Context, collection dbus.ObjectPath, attributes map[string]string) ([]dbus.ObjectPath, error) {
	f.calls = append(f.calls, "searchItems")
	f.searched = collection
	f.attributes = attributes
	c, ok := f.collections[collection]
	if !ok {
		return nil, errors.New("searchItems asked for a collection the fake never advertised")
	}
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	var items []dbus.ObjectPath
	for path, item := range c.items {
		if item.application == attributes["application"] && attributes[secretSchemaAttribute] == chromiumSecretSchema {
			items = append(items, path)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })
	return items, nil
}

func (f *fakeSecretService) getSecret(_ context.Context, item, session dbus.ObjectPath) ([]byte, error) {
	f.calls = append(f.calls, "getSecret")
	if session != fakeSession {
		return nil, errors.New("getSecret used a session the fake never opened")
	}
	for _, c := range f.collections {
		secret, ok := c.items[item]
		if !ok {
			continue
		}
		if c.locked {
			return nil, errors.New("getSecret read an item in a locked collection")
		}
		return secret.secret, f.secretErr
	}
	return nil, errors.New("getSecret asked for an item the fake never returned")
}

func (f *fakeSecretService) close() {
	f.calls = append(f.calls, "close")
	f.closed = true
}

func dialFake(f *fakeSecretService) secretServiceDialer {
	return func(context.Context) (secretService, error) { return f, nil }
}

func dialFailing(err error) secretServiceDialer {
	return func(context.Context) (secretService, error) { return nil, err }
}

func TestLookupSafeStorageOutcomes(t *testing.T) {
	busDown := &SecretServiceError{Op: "connect to the session bus", Err: errors.New("dial unix: connection refused")}
	busErr := func(op string) *SecretServiceError {
		return &SecretServiceError{Op: op, Err: errors.New("org.freedesktop.DBus.Error.Failed")}
	}
	staleChrome := chromeItem(fakeOtherItemPath, fakeStaleSecret)
	failing := func(set func(*fakeSecretService)) *fakeSecretService {
		f := unlockedDefault(chromeItem(fakeItemPath, fakeSecret))
		set(f)
		return f
	}
	full := []string{"readAlias", "unlock", "openSession", "searchItems", "getSecret", "close"}
	searchedEmpty := []string{"readAlias", "unlock", "openSession", "searchItems", "close"}
	cases := []struct {
		name         string
		dial         func(*fakeSecretService) secretServiceDialer
		fake         *fakeSecretService
		wantPassword SafeStorageKey
		wantErr      error
		wantCalls    []string
	}{
		{
			name:         "no session bus or no service owner is the basic store",
			dial:         func(*fakeSecretService) secretServiceDialer { return dialFailing(errNoSecretService) },
			fake:         &fakeSecretService{},
			wantPassword: basicStorePassword,
		},
		{
			name:    "a bus that cannot be reached is an error never the basic store",
			dial:    func(*fakeSecretService) secretServiceDialer { return dialFailing(busDown) },
			fake:    &fakeSecretService{},
			wantErr: busDown,
		},
		{
			name:         "no default collection is the basic store even beside another collection's Chrome item",
			dial:         dialFake,
			fake:         (&fakeSecretService{alias: noCollectionPath, prompt: noPromptPath}).withOther(staleChrome),
			wantPassword: basicStorePassword,
			wantCalls:    []string{"readAlias", "close"},
		},
		{
			name:         "unlocked default with no item is the basic store",
			dial:         dialFake,
			fake:         unlockedDefault(nil),
			wantPassword: basicStorePassword,
			wantCalls:    searchedEmpty,
		},
		{
			name:         "default item for another application is the basic store",
			dial:         dialFake,
			fake:         unlockedDefault(map[dbus.ObjectPath]fakeItem{fakeItemPath: {application: "other-app", secret: []byte(fakeStaleSecret)}}),
			wantPassword: basicStorePassword,
			wantCalls:    searchedEmpty,
		},
		{
			name:         "no default item is the basic store even when another unlocked collection holds a stale Chrome item",
			dial:         dialFake,
			fake:         unlockedDefault(nil).withOther(staleChrome),
			wantPassword: basicStorePassword,
			wantCalls:    searchedEmpty,
		},
		{
			name:         "unlocked default item yields its secret",
			dial:         dialFake,
			fake:         unlockedDefault(chromeItem(fakeItemPath, fakeSecret)),
			wantPassword: SafeStorageKey(fakeSecret),
			wantCalls:    full,
		},
		{
			name:         "default item wins over a stale item in another unlocked collection",
			dial:         dialFake,
			fake:         unlockedDefault(chromeItem(fakeItemPath, fakeSecret)).withOther(staleChrome),
			wantPassword: SafeStorageKey(fakeSecret),
			wantCalls:    full,
		},
		{
			name:         "locked default the service unlocks without a prompt yields its secret",
			dial:         dialFake,
			fake:         lockedDefault(noPromptPath, chromeItem(fakeItemPath, fakeSecret)),
			wantPassword: SafeStorageKey(fakeSecret),
			wantCalls:    full,
		},
		{
			name:      "locked default that needs a prompt is an error and an unlocked non-default is never read",
			dial:      dialFake,
			fake:      lockedDefault(fakePrompt, chromeItem(fakeItemPath, fakeSecret)).withOther(staleChrome),
			wantErr:   ErrSecretServiceLocked,
			wantCalls: []string{"readAlias", "unlock", "close"},
		},
		{
			name:      "locked default with no item still needs the prompt and is an error",
			dial:      dialFake,
			fake:      lockedDefault(fakePrompt, nil).withOther(staleChrome),
			wantErr:   ErrSecretServiceLocked,
			wantCalls: []string{"readAlias", "unlock", "close"},
		},
		{
			name:      "alias read failure is an error",
			dial:      dialFake,
			fake:      &fakeSecretService{aliasErr: busErr("ReadAlias")},
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"readAlias", "close"},
		},
		{
			name:      "unlock failure is an error",
			dial:      dialFake,
			fake:      failing(func(f *fakeSecretService) { f.unlockErr = busErr("Unlock") }),
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"readAlias", "unlock", "close"},
		},
		{
			name:      "session failure is an error",
			dial:      dialFake,
			fake:      failing(func(f *fakeSecretService) { f.sessionErr = busErr("OpenSession") }),
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"readAlias", "unlock", "openSession", "close"},
		},
		{
			name:      "search failure is an error",
			dial:      dialFake,
			fake:      failing(func(f *fakeSecretService) { f.searchErr = busErr("SearchItems") }),
			wantErr:   &SecretServiceError{},
			wantCalls: searchedEmpty,
		},
		{
			name:      "secret read failure is an error",
			dial:      dialFake,
			fake:      failing(func(f *fakeSecretService) { f.secretErr = busErr("GetSecret") }),
			wantErr:   &SecretServiceError{},
			wantCalls: full,
		},
		{
			name:      "empty secret is an error",
			dial:      dialFake,
			fake:      unlockedDefault(chromeItem(fakeItemPath, "")),
			wantErr:   &SecretServiceError{},
			wantCalls: full,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			password, err := lookupSafeStorage(context.Background(), tc.dial(tc.fake), "chrome")
			if password == SafeStorageKey(fakeStaleSecret) {
				t.Fatal("password is the secret of a collection other than default")
			}
			if tc.wantErr != nil {
				assertLookupError(t, err, tc.wantErr)
				if password != "" {
					t.Fatalf("password = %q on error, want empty", password)
				}
			} else {
				if err != nil {
					t.Fatalf("lookupSafeStorage: %v", err)
				}
				if password != tc.wantPassword {
					t.Fatalf("password = %q, want %q", password, tc.wantPassword)
				}
			}
			if got, want := strings.Join(tc.fake.calls, " "), strings.Join(tc.wantCalls, " "); got != want {
				t.Fatalf("calls = %q, want %q", got, want)
			}
			if len(tc.wantCalls) > 0 && !tc.fake.closed {
				t.Fatalf("connection not closed")
			}
			if !strings.Contains(strings.Join(tc.wantCalls, " "), "searchItems") {
				return
			}
			if tc.fake.searched != fakeDefaultCollection {
				t.Fatalf("searched collection %q, want the default %q", tc.fake.searched, fakeDefaultCollection)
			}
			wantAttributes := map[string]string{"application": "chrome", secretSchemaAttribute: chromiumSecretSchema}
			if len(tc.fake.attributes) != len(wantAttributes) {
				t.Fatalf("search attributes = %v, want %v", tc.fake.attributes, wantAttributes)
			}
			for k, v := range wantAttributes {
				if tc.fake.attributes[k] != v {
					t.Fatalf("search attribute %q = %q, want %q", k, tc.fake.attributes[k], v)
				}
			}
		})
	}
}

func assertLookupError(t *testing.T, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want %v", want)
	}
	if strings.Contains(err.Error(), fakeSecret) || strings.Contains(err.Error(), fakeStaleSecret) {
		t.Fatalf("error text carries a secret: %q", err.Error())
	}
	var wantSvc, svcErr *SecretServiceError
	if errors.As(want, &wantSvc) {
		if !errors.As(err, &svcErr) {
			t.Fatalf("err = %v, want *SecretServiceError", err)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestSessionBusAddressNeverAutolaunches(t *testing.T) {
	runtimeDir := t.TempDir()
	cases := []struct {
		name    string
		env     string
		runtime string
		want    string
		wantOK  bool
	}{
		{name: "explicit address wins", env: "unix:path=/tmp/explicit", runtime: runtimeDir, want: "unix:path=/tmp/explicit", wantOK: true},
		{name: "autolaunch is no address", env: "autolaunch:", runtime: "", wantOK: false},
		{name: "no env and no runtime dir is no address", env: "", runtime: "", wantOK: false},
		{name: "runtime dir without a bus socket is no address", env: "", runtime: runtimeDir, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", tc.env)
			t.Setenv("XDG_RUNTIME_DIR", tc.runtime)
			got, ok := sessionBusAddress()
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("sessionBusAddress() = %q, %v; want %q, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
	t.Run("runtime dir bus socket is used", func(t *testing.T) {
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
		t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
		if err := os.WriteFile(runtimeDir+"/bus", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		got, ok := sessionBusAddress()
		if !ok || got != "unix:path="+runtimeDir+"/bus" {
			t.Fatalf("sessionBusAddress() = %q, %v", got, ok)
		}
	})
}

// busSecretService is a minimal org.freedesktop.Secret.Service exported on a real
// session bus: its "default" alias names fakeDefaultCollection, and Unlock needs
// a prompt for every object while locked is set.
type busSecretService struct {
	locked atomic.Bool
}

func (s *busSecretService) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	if name != defaultCollectionAlias {
		return noCollectionPath, nil
	}
	return fakeDefaultCollection, nil
}

func (s *busSecretService) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	if s.locked.Load() {
		return []dbus.ObjectPath{}, fakePrompt, nil
	}
	return objects, noPromptPath, nil
}

func (s *busSecretService) OpenSession(algorithm string, _ dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	if algorithm != plainSessionAlgorithm {
		return dbus.Variant{}, "", dbus.MakeFailedError(errors.New("unsupported algorithm"))
	}
	return dbus.MakeVariant(""), fakeSession, nil
}

// busSecretCollection is one org.freedesktop.Secret.Collection exported on the
// bus: one Chrome-schema item per application in items.
type busSecretCollection struct {
	items map[string]dbus.ObjectPath
}

func (c *busSecretCollection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	if attributes[secretSchemaAttribute] != chromiumSecretSchema {
		return []dbus.ObjectPath{}, nil
	}
	if item, ok := c.items[attributes["application"]]; ok {
		return []dbus.ObjectPath{item}, nil
	}
	return []dbus.ObjectPath{}, nil
}

type busSecretItem struct {
	value []byte
}

func (i *busSecretItem) GetSecret(session dbus.ObjectPath) (dbusSecret, *dbus.Error) {
	if session != fakeSession {
		return dbusSecret{}, dbus.MakeFailedError(errors.New("unknown session"))
	}
	return dbusSecret{Session: session, Parameters: []byte{}, Value: i.value, ContentType: "text/plain"}, nil
}

func TestSecretServiceOverRealSessionBus(t *testing.T) {
	if os.Getenv("COOKIESYNC_SMOKE_DBUS") != "1" {
		t.Skip("set COOKIESYNC_SMOKE_DBUS=1 and run under dbus-run-session")
	}
	address, ok := sessionBusAddress()
	if !ok {
		t.Fatal("COOKIESYNC_SMOKE_DBUS=1 but no session bus address: run under dbus-run-session")
	}
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatalf("connect session bus: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	reply, err := conn.RequestName(secretServiceName, dbus.NameFlagDoNotQueue)
	if err != nil {
		t.Fatalf("RequestName: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName reply = %v, want primary owner (a real Secret Service is running on this bus)", reply)
	}
	svc := &busSecretService{}
	if err := conn.Export(svc, secretServicePath, secretServiceIface); err != nil {
		t.Fatalf("export service: %v", err)
	}
	exports := []struct {
		object any
		path   dbus.ObjectPath
		iface  string
	}{
		{&busSecretCollection{items: map[string]dbus.ObjectPath{"chrome": fakeItemPath}}, fakeDefaultCollection, secretCollectionIface},
		{&busSecretCollection{items: map[string]dbus.ObjectPath{"chrome": fakeOtherItemPath, "chromium": fakeOtherItemPath}}, fakeOtherCollection, secretCollectionIface},
		{&busSecretItem{value: []byte(fakeSecret)}, fakeItemPath, secretItemIface},
		{&busSecretItem{value: []byte(fakeStaleSecret)}, fakeOtherItemPath, secretItemIface},
	}
	for _, e := range exports {
		if err := conn.Export(e.object, e.path, e.iface); err != nil {
			t.Fatalf("export %s: %v", e.path, err)
		}
	}
	ctx := context.Background()

	key, err := LinuxConsent{}.ObtainKeyUnprompted(ctx, Browser{SecretServiceApplication: "chrome"})
	if err != nil {
		t.Fatalf("ObtainKeyUnprompted(chrome): %v", err)
	}
	if want := DeriveKey(SafeStorageKey(fakeSecret)); !bytes.Equal(key, want) {
		t.Fatalf("chrome key = %x, want the key derived from the default collection's secret", key)
	}

	key, err = LinuxConsent{}.ObtainKeyUnprompted(ctx, Browser{SecretServiceApplication: "chromium"})
	if err != nil {
		t.Fatalf("ObtainKeyUnprompted(chromium): %v", err)
	}
	if !bytes.Equal(key, linuxBasicKey) {
		t.Fatalf("chromium key = %x, want the basic-store key (no item in the default collection)", key)
	}

	svc.locked.Store(true)
	key, err = LinuxConsent{}.ObtainKeyUnprompted(ctx, Browser{SecretServiceApplication: "chrome"})
	if !errors.Is(err, ErrSecretServiceLocked) {
		t.Fatalf("ObtainKeyUnprompted(chrome) over a locked default = %x, %v; want ErrSecretServiceLocked", key, err)
	}
	if key != nil {
		t.Fatalf("locked default key = %x, want nil", key)
	}
}
