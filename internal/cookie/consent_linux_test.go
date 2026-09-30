//go:build linux

package cookie

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func linuxChrome(t *testing.T) Browser {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	b, err := Lookup(BrowserName("chrome"))
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	return b
}

// neverDial fails the test if a presence-gated method reaches for the Secret
// Service at all.
func neverDial(t *testing.T) secretServiceDialer {
	return func(context.Context) (secretService, error) {
		t.Fatal("presence-gated release read the Secret Service")
		return nil, nil
	}
}

func TestLinuxConsentPresenceGatedMethodsFailClosedAsUnavailable(t *testing.T) {
	c := LinuxConsent{secrets: neverDial(t)}
	ctx := context.Background()
	browser := linuxChrome(t)
	cases := []struct {
		name string
		call func() (any, error)
	}{
		{name: "ObtainKey", call: func() (any, error) { return c.ObtainKey(ctx, browser, "post a tweet") }},
		{name: "ObtainKeys", call: func() (any, error) { return c.ObtainKeys(ctx, []Browser{browser}, "post a tweet") }},
		{name: "ObtainKeyBiometric", call: func() (any, error) { return c.ObtainKeyBiometric(ctx, browser, "post a tweet") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if err == nil {
				t.Fatalf("%s released without a presence gate: %v", tc.name, got)
			}
			switch v := got.(type) {
			case AesKey:
				if v != nil {
					t.Fatalf("%s key = %x, want nil", tc.name, v)
				}
			case []KeyOutcome:
				if v != nil {
					t.Fatalf("%s outcomes = %+v, want nil", tc.name, v)
				}
			default:
				t.Fatalf("%s returned %T", tc.name, got)
			}
			// auth.Classify maps ErrKeybagLocked to VerdictUnavailable before it
			// looks at ConsentError, so this is the whole Unavailable proof.
			if !errors.Is(err, ErrKeybagLocked) {
				t.Fatalf("%s err = %v, want it to wrap ErrKeybagLocked", tc.name, err)
			}
			var consentErr *ConsentError
			if !errors.As(err, &consentErr) {
				t.Fatalf("%s err = %v, want *ConsentError like the Darwin presence-unavailable exit", tc.name, err)
			}
			if !strings.Contains(consentErr.Msg, "attended peer") {
				t.Fatalf("%s msg = %q, want it to name the routed approval", tc.name, consentErr.Msg)
			}
		})
	}
}

func TestLinuxConsentUnpromptedReadDerivesFromSecretOrBasicStore(t *testing.T) {
	browser := linuxChrome(t)
	cases := []struct {
		name    string
		dial    secretServiceDialer
		fake    *fakeSecretService
		wantKey AesKey
	}{
		{
			name:    "no secret service derives the basic-store key",
			dial:    dialFailing(errNoSecretService),
			wantKey: linuxBasicKey,
		},
		{
			name:    "no item derives the basic-store key",
			fake:    &fakeSecretService{prompt: noPromptPath},
			wantKey: linuxBasicKey,
		},
		{
			name:    "an item derives the key from its secret",
			fake:    &fakeSecretService{unlocked: []dbus.ObjectPath{fakeItemPath}, prompt: noPromptPath, secret: []byte(fakeSecret)},
			wantKey: DeriveKey(SafeStorageKey(fakeSecret)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial := tc.dial
			if tc.fake != nil {
				dial = dialFake(tc.fake)
			}
			key, err := LinuxConsent{secrets: dial}.ObtainKeyUnprompted(context.Background(), browser)
			if err != nil {
				t.Fatalf("ObtainKeyUnprompted: %v", err)
			}
			if !bytes.Equal(key, tc.wantKey) {
				t.Fatalf("key = %x, want %x", key, tc.wantKey)
			}
			if tc.fake != nil && tc.fake.attributes["application"] != browser.SecretServiceApplication {
				t.Fatalf("searched application %q, want the browser's %q", tc.fake.attributes["application"], browser.SecretServiceApplication)
			}
		})
	}
	if bytes.Equal(DeriveKey(SafeStorageKey(fakeSecret)), linuxBasicKey) {
		t.Fatal("the synthetic secret must not derive the basic-store key")
	}
}

func TestLinuxConsentUnpromptedReadFailsOnLockedOrBrokenService(t *testing.T) {
	browser := linuxChrome(t)
	cases := []struct {
		name    string
		dial    secretServiceDialer
		wantErr error
	}{
		{
			name:    "locked collection",
			dial:    dialFake(&fakeSecretService{locked: []dbus.ObjectPath{fakeLockedPath}, prompt: fakePrompt, secret: []byte(fakeSecret)}),
			wantErr: ErrSecretServiceLocked,
		},
		{
			name:    "unreachable bus",
			dial:    dialFailing(&SecretServiceError{Op: "connect to the session bus", Err: errors.New("dial unix: connection refused")}),
			wantErr: &SecretServiceError{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := LinuxConsent{secrets: tc.dial}.ObtainKeyUnprompted(context.Background(), browser)
			if key != nil {
				t.Fatalf("key = %x, want nil", key)
			}
			assertLookupError(t, err, tc.wantErr)
			if errors.Is(err, ErrKeybagLocked) {
				t.Fatalf("err = %v must not read as presence-unavailable: the key read is local and cannot route", err)
			}
			var consentErr *ConsentError
			if errors.As(err, &consentErr) {
				t.Fatalf("err = %v must not read as a declined prompt", err)
			}
		})
	}
}
