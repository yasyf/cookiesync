package daemon

import (
	"context"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// TestHandleRequestBridgeConsentApprovedIsStrictBiometric proves an approved
// bridge consent echoes the requester's nonce + endpoint VERBATIM and takes the
// STRICT biometric seam — never the passcode-capable ObtainKeys.
func TestHandleRequestBridgeConsentApprovedIsStrictBiometric(t *testing.T) {
	me := currentUser(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestBridgeConsent(context.Background(), map[string]any{
		"browser": "chrome", "profile": "Work", "nonce": "n-1", "endpoint": "them@host:chrome:Work",
	})
	if err != nil {
		t.Fatalf("handleRequestBridgeConsent: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"them@host:chrome:Work","nonce":"n-1","status":"approved"}` {
		t.Fatalf("approved = %s", marshalResult(t, got))
	}
	if got := consent.biometricCalls.Load(); got != 1 {
		t.Fatalf("ObtainKeyBiometric calls = %d, want 1", got)
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("bridge consent must not use the passcode-capable path, got prompts %v", consent.promptedReasons)
	}
}

// TestHandleRequestBridgeConsentVerdicts proves each release outcome maps to the
// right wire status, including the vault-missing special case that routes on
// (unavailable) rather than terminating as a denial.
func TestHandleRequestBridgeConsentVerdicts(t *testing.T) {
	me := currentUser(t)
	tests := []struct {
		name          string
		onConsole     bool
		obtainErr     error
		wantStatus    string
		wantBiometric int32
	}{
		{
			name:       "no live session is unavailable, never taps",
			onConsole:  false,
			wantStatus: `{"status":"unavailable"}`,
		},
		{
			name:          "decline is denied",
			onConsole:     true,
			obtainErr:     &cookie.ConsentError{Msg: "Touch ID (biometric) was cancelled or denied"},
			wantStatus:    `{"status":"denied"}`,
			wantBiometric: 1,
		},
		{
			name:      "locked keybag is unavailable",
			onConsole: true,
			obtainErr: &cookie.ConsentError{
				Msg: "biometric authentication unavailable",
				Err: cookie.ErrKeybagLocked,
			},
			wantStatus:    `{"status":"unavailable"}`,
			wantBiometric: 1,
		},
		{
			name:      "missing bridge vault routes on (unavailable), not denied",
			onConsole: true,
			obtainErr: &cookie.ConsentError{
				Msg: "bridge vault missing — re-enroll",
				Err: cookie.ErrBridgeVaultMissing,
			},
			wantStatus:    `{"status":"unavailable"}`,
			wantBiometric: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeMesh(t, "me@laptop")
			st := stateWith("me@laptop", "")
			probe := staticProbe(SessionSnapshot{OnConsole: false})
			if tc.onConsole {
				probe = staticProbe(liveSession(me))
			}
			consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")), obtainErr: tc.obtainErr}
			d := New(consent, newFakeCache(), nil, probe, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

			got, err := d.handleRequestBridgeConsent(context.Background(), map[string]any{
				"browser": "chrome", "nonce": "n", "endpoint": "them@host:chrome:Default",
			})
			if err != nil {
				t.Fatalf("handleRequestBridgeConsent: %v", err)
			}
			if marshalResult(t, got) != tc.wantStatus {
				t.Fatalf("status = %s, want %s", marshalResult(t, got), tc.wantStatus)
			}
			if got := consent.biometricCalls.Load(); got != tc.wantBiometric {
				t.Fatalf("ObtainKeyBiometric calls = %d, want %d", got, tc.wantBiometric)
			}
		})
	}
}
