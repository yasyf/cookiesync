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
	secretServiceName     = "org.freedesktop.secrets"
	secretServicePath     = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceIface    = "org.freedesktop.Secret.Service"
	secretItemIface       = "org.freedesktop.Secret.Item"
	secretSchemaAttribute = "xdg:schema"
	chromiumSecretSchema  = "chrome_libsecret_os_crypt_password_v2"
	plainSessionAlgorithm = "plain"
	noPromptPath          = dbus.ObjectPath("/")
	basicStorePassword    = SafeStorageKey("peanuts")
)

// ErrSecretServiceLocked reports that the browser's Safe Storage item exists but
// its collection is locked and unlocking it needs an interactive prompt, which
// this host never shows. The basic-store password is no substitute for it.
var ErrSecretServiceLocked = errors.New("secret service collection is locked and needs a prompt to unlock")

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
	searchItems(ctx context.Context, attributes map[string]string) (unlocked, locked []dbus.ObjectPath, err error)
	unlock(ctx context.Context, objects []dbus.ObjectPath) (unlocked []dbus.ObjectPath, prompt dbus.ObjectPath, err error)
	openSession(ctx context.Context) (dbus.ObjectPath, error)
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
// cookies with: the Secret Service item's secret when one exists, the basic-store
// password when there is no Secret Service or no item. A locked collection or any
// bus failure is an error, never the basic-store password.
func lookupSafeStorage(ctx context.Context, dial secretServiceDialer, application string) (SafeStorageKey, error) {
	svc, err := dial(ctx)
	if errors.Is(err, errNoSecretService) {
		return basicStorePassword, nil
	}
	if err != nil {
		return "", err
	}
	defer svc.close()
	attributes := map[string]string{"application": application, secretSchemaAttribute: chromiumSecretSchema}
	unlocked, locked, err := svc.searchItems(ctx, attributes)
	if err != nil {
		return "", err
	}
	if len(unlocked) == 0 && len(locked) == 0 {
		return basicStorePassword, nil
	}
	if len(unlocked) == 0 {
		unlocked, err = unlockWithoutPrompt(ctx, svc, locked)
		if err != nil {
			return "", err
		}
	}
	session, err := svc.openSession(ctx)
	if err != nil {
		return "", err
	}
	secret, err := svc.getSecret(ctx, unlocked[0], session)
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

func (s *dbusSecretService) searchItems(ctx context.Context, attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	if err := s.service.CallWithContext(ctx, secretServiceIface+".SearchItems", dbus.FlagNoAutoStart, attributes).Store(&unlocked, &locked); err != nil {
		return nil, nil, &SecretServiceError{Op: "SearchItems", Err: err}
	}
	return unlocked, locked, nil
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
