//go:build linux

package cookie

import "context"

// LinuxConsent is the Linux key provider. This host has no user-presence gate, so
// every locally gated release fails closed as unavailable and the existing routed
// consent asks an attended peer; the unprompted read after that approval takes
// the Safe Storage password from the Secret Service, or Chromium's basic-store
// password when there is none. The zero value dials the real session bus.
type LinuxConsent struct {
	secrets secretServiceDialer
}

// ObtainKeyUnprompted derives browser's key from its Secret Service item, or from
// the basic-store password when this host has no Secret Service or no item. For
// the owning host only, after a routed approval has already gated the release.
func (c LinuxConsent) ObtainKeyUnprompted(ctx context.Context, browser Browser) (AesKey, error) {
	password, err := lookupSafeStorage(ctx, c.dialer(), browser.SecretServiceApplication)
	if err != nil {
		return nil, err
	}
	return DeriveKey(password), nil
}

// ObtainKey fails closed: no user-presence gate exists on this host.
func (LinuxConsent) ObtainKey(context.Context, Browser, string) (AesKey, error) {
	return nil, noPresenceGate()
}

// ObtainKeys fails closed: no user-presence gate exists on this host.
func (LinuxConsent) ObtainKeys(context.Context, []Browser, string) ([]KeyOutcome, error) {
	return nil, noPresenceGate()
}

// ObtainKeyBiometric fails closed: no biometric gate exists on this host.
func (LinuxConsent) ObtainKeyBiometric(context.Context, Browser, string) (AesKey, error) {
	return nil, noPresenceGate()
}

func (c LinuxConsent) dialer() secretServiceDialer {
	if c.secrets != nil {
		return c.secrets
	}
	return dialSecretService
}

// noPresenceGate is the presence-unavailable error the Darwin path returns on a
// locked keybag, so the existing classifiers answer Unavailable and routed consent
// moves on to an attended peer instead of denying or releasing.
func noPresenceGate() error {
	return &ConsentError{Msg: "no user-presence gate on this host; consent must be approved on an attended peer", Err: ErrKeybagLocked}
}
