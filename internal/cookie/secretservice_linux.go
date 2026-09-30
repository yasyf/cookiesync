//go:build linux

package cookie

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/godbus/dbus/v5"
)

const (
	secretServiceName      = "org.freedesktop.secrets"
	secretServicePath      = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceIface     = "org.freedesktop.Secret.Service"
	secretCollectionIface  = "org.freedesktop.Secret.Collection"
	secretItemIface        = "org.freedesktop.Secret.Item"
	secretSchemaAttribute  = "xdg:schema"
	chromiumSecretSchema   = "chrome_libsecret_os_crypt_password_v2"
	defaultCollectionAlias = "default"
	plainSessionAlgorithm  = "plain"
	noPromptPath           = dbus.ObjectPath("/")
	noCollectionPath       = dbus.ObjectPath("/")
	basicStorePassword     = SafeStorageKey("peanuts")
)

// ErrSecretServiceLocked reports that the default Secret Service collection is
// locked and unlocking it needs an interactive prompt, which this host never
// shows; whether it holds the browser's Safe Storage item is unknowable, so the
// basic-store password is no substitute.
var ErrSecretServiceLocked = errors.New("secret service default collection is locked and needs a prompt to unlock")

// errNoSecretService: no session bus, or nobody owns org.freedesktop.secrets on
// it. Chromium then encrypts with the basic-store password.
var errNoSecretService = errors.New("no secret service on the session bus")

// SecretServiceError reports a D-Bus failure while reading the Safe Storage item:
// Op is the call that failed, Err the bus error. It never carries the secret.
type SecretServiceError struct {
	Op  string
	Err error
}

func (e *SecretServiceError) Error() string { return "secret service " + e.Op + ": " + e.Err.Error() }

func (e *SecretServiceError) Unwrap() error { return e.Err }

// secretService is the slice of the freedesktop Secret Service API the Linux Safe
// Storage read consumes; dbusSecretService satisfies it over the session bus.
type secretService interface {
	readAlias(ctx context.Context, name string) (dbus.ObjectPath, error)
	unlock(ctx context.Context, objects []dbus.ObjectPath) (unlocked []dbus.ObjectPath, prompt dbus.ObjectPath, err error)
	openSession(ctx context.Context) (dbus.ObjectPath, error)
	searchItems(ctx context.Context, collection dbus.ObjectPath, attributes map[string]string) ([]dbus.ObjectPath, error)
	getSecret(ctx context.Context, item, session dbus.ObjectPath) ([]byte, error)
	close()
}

// secretServiceDialer connects to the session bus's Secret Service, or reports
// errNoSecretService when there is no bus or no owner of the service name.
type secretServiceDialer func(ctx context.Context) (secretService, error)

// dbusSecret is the org.freedesktop.Secret.Item GetSecret reply: (oayays).
type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type dbusSecretService struct {
	conn    *dbus.Conn
	service dbus.BusObject
}

// lookupSafeStorage reads the Safe Storage password Chromium keyed application's
// cookies with, the way Chrome's FreedesktopSecretKeyProvider does: the item in
// the "default" collection, or the basic-store password when there is no Secret
// Service, no default collection, or no item there. Other collections are never
// read. A locked default collection or any bus failure is an error.
func lookupSafeStorage(ctx context.Context, dial secretServiceDialer, application string) (SafeStorageKey, error) {
	svc, err := dial(ctx)
	if errors.Is(err, errNoSecretService) {
		return basicStorePassword, nil
	}
	if err != nil {
		return "", err
	}
	defer svc.close()
	collection, err := svc.readAlias(ctx, defaultCollectionAlias)
	if err != nil {
		return "", err
	}
	if collection == noCollectionPath {
		return basicStorePassword, nil
	}
	if _, err := unlockWithoutPrompt(ctx, svc, []dbus.ObjectPath{collection}); err != nil {
		return "", err
	}
	session, err := svc.openSession(ctx)
	if err != nil {
		return "", err
	}
	attributes := map[string]string{"application": application, secretSchemaAttribute: chromiumSecretSchema}
	items, err := svc.searchItems(ctx, collection, attributes)
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return basicStorePassword, nil
	}
	secret, err := svc.getSecret(ctx, items[0], session)
	if err != nil {
		return "", err
	}
	if len(secret) == 0 {
		return "", &SecretServiceError{Op: "GetSecret", Err: errors.New("item holds an empty secret")}
	}
	return SafeStorageKey(secret), nil
}

// unlockWithoutPrompt asks the service to unlock objects and accepts only an
// answer that needed no prompt; a prompt object is never invoked.
func unlockWithoutPrompt(ctx context.Context, svc secretService, objects []dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	unlocked, prompt, err := svc.unlock(ctx, objects)
	if err != nil {
		return nil, err
	}
	if prompt != noPromptPath || len(unlocked) == 0 {
		return nil, ErrSecretServiceLocked
	}
	return unlocked, nil
}

// dialSecretService connects to the session bus without ever launching one and
// checks that org.freedesktop.secrets has an owner, without activating it.
func dialSecretService(ctx context.Context) (secretService, error) {
	address, ok := sessionBusAddress()
	if !ok {
		return nil, errNoSecretService
	}
	conn, err := dbus.Connect(address, dbus.WithContext(ctx))
	if err != nil {
		return nil, &SecretServiceError{Op: "connect to the session bus", Err: err}
	}
	var owned bool
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", dbus.FlagNoAutoStart, secretServiceName).Store(&owned); err != nil {
		_ = conn.Close()
		return nil, &SecretServiceError{Op: "NameHasOwner", Err: err}
	}
	if !owned {
		_ = conn.Close()
		return nil, errNoSecretService
	}
	return &dbusSecretService{conn: conn, service: conn.Object(secretServiceName, secretServicePath)}, nil
}

// sessionBusAddress resolves the session bus the way libdbus does, minus
// autolaunch: $DBUS_SESSION_BUS_ADDRESS, else $XDG_RUNTIME_DIR/bus when that
// socket exists. "autolaunch:" counts as no address.
func sessionBusAddress() (string, bool) {
	if address := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); address != "" && address != "autolaunch:" {
		return address, true
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return "", false
	}
	socket := filepath.Join(runtimeDir, "bus")
	if _, err := os.Stat(socket); err != nil { //nolint:gosec // G703: the session bus socket lives under XDG_RUNTIME_DIR.
		return "", false
	}
	return "unix:path=" + dbus.EscapeBusAddressValue(socket), true
}

func (s *dbusSecretService) readAlias(ctx context.Context, name string) (dbus.ObjectPath, error) {
	var collection dbus.ObjectPath
	if err := s.service.CallWithContext(ctx, secretServiceIface+".ReadAlias", dbus.FlagNoAutoStart, name).Store(&collection); err != nil {
		return "", &SecretServiceError{Op: "ReadAlias", Err: err}
	}
	return collection, nil
}

func (s *dbusSecretService) searchItems(ctx context.Context, collection dbus.ObjectPath, attributes map[string]string) ([]dbus.ObjectPath, error) {
	var items []dbus.ObjectPath
	if err := s.conn.Object(secretServiceName, collection).CallWithContext(ctx, secretCollectionIface+".SearchItems", dbus.FlagNoAutoStart, attributes).Store(&items); err != nil {
		return nil, &SecretServiceError{Op: "SearchItems", Err: err}
	}
	return items, nil
}

func (s *dbusSecretService) unlock(ctx context.Context, objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, error) {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := s.service.CallWithContext(ctx, secretServiceIface+".Unlock", dbus.FlagNoAutoStart, objects).Store(&unlocked, &prompt); err != nil {
		return nil, "", &SecretServiceError{Op: "Unlock", Err: err}
	}
	return unlocked, prompt, nil
}

func (s *dbusSecretService) openSession(ctx context.Context) (dbus.ObjectPath, error) {
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := s.service.CallWithContext(ctx, secretServiceIface+".OpenSession", dbus.FlagNoAutoStart, plainSessionAlgorithm, dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return "", &SecretServiceError{Op: "OpenSession", Err: err}
	}
	return session, nil
}

func (s *dbusSecretService) getSecret(ctx context.Context, item, session dbus.ObjectPath) ([]byte, error) {
	var secret dbusSecret
	if err := s.conn.Object(secretServiceName, item).CallWithContext(ctx, secretItemIface+".GetSecret", dbus.FlagNoAutoStart, session).Store(&secret); err != nil {
		return nil, &SecretServiceError{Op: "GetSecret", Err: err}
	}
	return secret.Value, nil
}

func (s *dbusSecretService) close() {
	_ = s.conn.Close()
}
