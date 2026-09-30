//go:build linux

package cookie

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

const (
	fakeSecret     = "synthetic-safe-storage-secret"
	fakeItemPath   = dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	fakeLockedPath = dbus.ObjectPath("/org/freedesktop/secrets/collection/locked/1")
	fakeSession    = dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	fakePrompt     = dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")
)

// fakeSecretService scripts one Secret Service conversation and records every
// call it received, in order.
type fakeSecretService struct {
	calls      []string
	attributes map[string]string
	unlocked   []dbus.ObjectPath
	locked     []dbus.ObjectPath
	searchErr  error
	unlockErr  error
	prompt     dbus.ObjectPath
	sessionErr error
	secret     []byte
	secretErr  error
	closed     bool
}

func (f *fakeSecretService) searchItems(_ context.Context, attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, error) {
	f.calls = append(f.calls, "searchItems")
	f.attributes = attributes
	return f.unlocked, f.locked, f.searchErr
}

func (f *fakeSecretService) unlock(_ context.Context, objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, error) {
	f.calls = append(f.calls, "unlock")
	if f.unlockErr != nil {
		return nil, "", f.unlockErr
	}
	if f.prompt != noPromptPath {
		return nil, f.prompt, nil
	}
	return objects, noPromptPath, nil
}

func (f *fakeSecretService) openSession(context.Context) (dbus.ObjectPath, error) {
	f.calls = append(f.calls, "openSession")
	return fakeSession, f.sessionErr
}

func (f *fakeSecretService) getSecret(_ context.Context, item, session dbus.ObjectPath) ([]byte, error) {
	f.calls = append(f.calls, "getSecret")
	if session != fakeSession {
		return nil, errors.New("getSecret used a session the fake never opened")
	}
	if item != fakeItemPath && item != fakeLockedPath {
		return nil, errors.New("getSecret asked for an item the fake never returned")
	}
	return f.secret, f.secretErr
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
			name:         "service present with no matching item is the basic store",
			dial:         dialFake,
			fake:         &fakeSecretService{prompt: noPromptPath},
			wantPassword: basicStorePassword,
			wantCalls:    []string{"searchItems", "close"},
		},
		{
			name:         "unlocked item yields its secret",
			dial:         dialFake,
			fake:         &fakeSecretService{unlocked: []dbus.ObjectPath{fakeItemPath}, prompt: noPromptPath, secret: []byte(fakeSecret)},
			wantPassword: SafeStorageKey(fakeSecret),
			wantCalls:    []string{"searchItems", "openSession", "getSecret", "close"},
		},
		{
			name:         "locked item the service unlocks without a prompt yields its secret",
			dial:         dialFake,
			fake:         &fakeSecretService{locked: []dbus.ObjectPath{fakeLockedPath}, prompt: noPromptPath, secret: []byte(fakeSecret)},
			wantPassword: SafeStorageKey(fakeSecret),
			wantCalls:    []string{"searchItems", "unlock", "openSession", "getSecret", "close"},
		},
		{
			name:      "locked item that needs a prompt is an error and the prompt is never run",
			dial:      dialFake,
			fake:      &fakeSecretService{locked: []dbus.ObjectPath{fakeLockedPath}, prompt: fakePrompt, secret: []byte(fakeSecret)},
			wantErr:   ErrSecretServiceLocked,
			wantCalls: []string{"searchItems", "unlock", "close"},
		},
		{
			name:      "search failure is an error",
			dial:      dialFake,
			fake:      &fakeSecretService{searchErr: &SecretServiceError{Op: "SearchItems", Err: errors.New("org.freedesktop.DBus.Error.ServiceUnknown")}, secret: []byte(fakeSecret)},
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"searchItems", "close"},
		},
		{
			name:      "unlock failure is an error",
			dial:      dialFake,
			fake:      &fakeSecretService{locked: []dbus.ObjectPath{fakeLockedPath}, unlockErr: &SecretServiceError{Op: "Unlock", Err: errors.New("org.freedesktop.DBus.Error.Failed")}, secret: []byte(fakeSecret)},
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"searchItems", "unlock", "close"},
		},
		{
			name:      "session failure is an error",
			dial:      dialFake,
			fake:      &fakeSecretService{unlocked: []dbus.ObjectPath{fakeItemPath}, prompt: noPromptPath, sessionErr: &SecretServiceError{Op: "OpenSession", Err: errors.New("org.freedesktop.DBus.Error.NotSupported")}, secret: []byte(fakeSecret)},
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"searchItems", "openSession", "close"},
		},
		{
			name:      "secret read failure is an error",
			dial:      dialFake,
			fake:      &fakeSecretService{unlocked: []dbus.ObjectPath{fakeItemPath}, prompt: noPromptPath, secretErr: &SecretServiceError{Op: "GetSecret", Err: errors.New("org.freedesktop.Secret.Error.IsLocked")}, secret: []byte(fakeSecret)},
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"searchItems", "openSession", "getSecret", "close"},
		},
		{
			name:      "empty secret is an error",
			dial:      dialFake,
			fake:      &fakeSecretService{unlocked: []dbus.ObjectPath{fakeItemPath}, prompt: noPromptPath},
			wantErr:   &SecretServiceError{},
			wantCalls: []string{"searchItems", "openSession", "getSecret", "close"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			password, err := lookupSafeStorage(context.Background(), tc.dial(tc.fake), "chrome")
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
			if len(tc.wantCalls) > 0 {
				wantAttributes := map[string]string{"application": "chrome", secretSchemaAttribute: chromiumSecretSchema}
				if len(tc.fake.attributes) != len(wantAttributes) {
					t.Fatalf("search attributes = %v, want %v", tc.fake.attributes, wantAttributes)
				}
				for k, v := range wantAttributes {
					if tc.fake.attributes[k] != v {
						t.Fatalf("search attribute %q = %q, want %q", k, tc.fake.attributes[k], v)
					}
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
	if strings.Contains(err.Error(), fakeSecret) {
		t.Fatalf("error text carries the secret: %q", err.Error())
	}
	var svcErr *SecretServiceError
	if _, isSvc := want.(*SecretServiceError); isSvc {
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
// session bus: one unlocked item per application in items, one locked item per
// application in locked whose unlock always needs a prompt.
type busSecretService struct {
	items  map[string]dbus.ObjectPath
	locked map[string]dbus.ObjectPath
}

func (s *busSecretService) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	if attributes[secretSchemaAttribute] != chromiumSecretSchema {
		return []dbus.ObjectPath{}, []dbus.ObjectPath{}, nil
	}
	unlocked, locked := []dbus.ObjectPath{}, []dbus.ObjectPath{}
	if item, ok := s.items[attributes["application"]]; ok {
		unlocked = append(unlocked, item)
	}
	if item, ok := s.locked[attributes["application"]]; ok {
		locked = append(locked, item)
	}
	return unlocked, locked, nil
}

func (s *busSecretService) Unlock([]dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return []dbus.ObjectPath{}, fakePrompt, nil
}

func (s *busSecretService) OpenSession(algorithm string, _ dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	if algorithm != plainSessionAlgorithm {
		return dbus.Variant{}, "", dbus.MakeFailedError(errors.New("unsupported algorithm"))
	}
	return dbus.MakeVariant(""), fakeSession, nil
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
	svc := &busSecretService{
		items:  map[string]dbus.ObjectPath{"chrome": fakeItemPath},
		locked: map[string]dbus.ObjectPath{"locked-app": fakeLockedPath},
	}
	if err := conn.Export(svc, secretServicePath, secretServiceIface); err != nil {
		t.Fatalf("export service: %v", err)
	}
	if err := conn.Export(&busSecretItem{value: []byte(fakeSecret)}, fakeItemPath, secretItemIface); err != nil {
		t.Fatalf("export item: %v", err)
	}
	if err := conn.Export(&busSecretItem{value: []byte(fakeSecret)}, fakeLockedPath, secretItemIface); err != nil {
		t.Fatalf("export locked item: %v", err)
	}
	ctx := context.Background()

	key, err := LinuxConsent{}.ObtainKeyUnprompted(ctx, Browser{SecretServiceApplication: "chrome"})
	if err != nil {
		t.Fatalf("ObtainKeyUnprompted(chrome): %v", err)
	}
	if want := DeriveKey(SafeStorageKey(fakeSecret)); !bytes.Equal(key, want) {
		t.Fatalf("chrome key = %x, want the key derived from the exported secret", key)
	}

	key, err = LinuxConsent{}.ObtainKeyUnprompted(ctx, Browser{SecretServiceApplication: "chromium"})
	if err != nil {
		t.Fatalf("ObtainKeyUnprompted(chromium): %v", err)
	}
	if !bytes.Equal(key, linuxBasicKey) {
		t.Fatalf("chromium key = %x, want the basic-store key (no item)", key)
	}

	key, err = LinuxConsent{}.ObtainKeyUnprompted(ctx, Browser{SecretServiceApplication: "locked-app"})
	if !errors.Is(err, ErrSecretServiceLocked) {
		t.Fatalf("ObtainKeyUnprompted(locked-app) = %x, %v; want ErrSecretServiceLocked", key, err)
	}
	if key != nil {
		t.Fatalf("locked-app key = %x, want nil", key)
	}
}
