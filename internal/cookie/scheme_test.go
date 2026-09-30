package cookie

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Synthetic Linux vectors: the public basic-store key over goldenValue at goldenHost,
// and a made-up keyring secret. Blobs were produced independently with openssl.
const (
	linuxBasicKeyHex   = "fd621fe5a2b402539dfa147ca9272778"
	linuxKeyringSecret = SafeStorageKey("synthetic-keyring-secret")
	linuxKeyringKeyHex = "47c6210f9581717cb859cf466dddfc38"
	linuxV10HashedHex  = "7631301bb654833fa6f8a731528db92d657dc37c87544a81ba7875d0681273543b4e4f16e9f59abe35b5cc88d66dbecc4667695a5a4acc41244add885b1187d4a0c87c"
	linuxV10PlainHex   = "7631300b4d86cda0526e024beac62c4e3de014c40e52c3482d55ee526cf5d1c4031588"
	linuxV11HashedHex  = "76313174bf46dc4bb7815df0361a2540d71bce3a093daa4e2363890cf05ab9e5163d4819da6233c47eb76cc40feac341425fa411812003937209051157682abd129b10"
	linuxV11PlainHex   = "76313164a869828b44d2a390bc4531861ee0fbc2313ceac4272f1583af25fac471ba7d"
)

var (
	lnx = linuxScheme{}
	mac = darwinScheme{}
)

func keyringKey(t *testing.T) AesKey {
	t.Helper()
	return lnx.deriveKey(linuxKeyringSecret)
}

func otherKeyringKey(t *testing.T) AesKey {
	t.Helper()
	return lnx.deriveKey(SafeStorageKey("another-synthetic-secret"))
}

func linuxSealed(t *testing.T, tag string, key AesKey, value string, host HostKey, version int) []byte {
	t.Helper()
	blob, err := lnx.seal(tag, key, value, host, version)
	if err != nil {
		t.Fatalf("seal %s: %v", tag, err)
	}
	return blob
}

func TestSchemeGoldenKeys(t *testing.T) {
	cases := []struct {
		id   string
		got  AesKey
		want string
	}{
		{"linux-basic-constant", linuxBasicKey, linuxBasicKeyHex},
		{"linux-derive-peanuts", lnx.deriveKey(SafeStorageKey("peanuts")), linuxBasicKeyHex},
		{"linux-derive-keyring", keyringKey(t), linuxKeyringKeyHex},
		{"darwin-derive-peanuts", mac.deriveKey(SafeStorageKey("peanuts")), goldenKeyHex},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if want := mustHex(t, c.want); !bytes.Equal(c.got, want) {
				t.Fatalf("key = %x, want %s", c.got, c.want)
			}
		})
	}
	if _, ok := linuxKeyringKey(linuxBasicKey); ok {
		t.Fatal("the basic-store key must never count as a keyring key")
	}
	if _, ok := linuxKeyringKey(keyringKey(t)); !ok {
		t.Fatal("a keyring-derived key must count as a keyring key")
	}
}

func TestSchemeLinuxGoldenVectors(t *testing.T) {
	cases := []struct {
		id      string
		blob    string
		tag     string
		sealKey AesKey
		openKey AesKey
		version int
	}{
		{"v10-hashed-basic-key", linuxV10HashedHex, "v10", linuxBasicKey, linuxBasicKey, 24},
		{"v10-hashed-keyring-key-in-hand", linuxV10HashedHex, "v10", linuxBasicKey, keyringKey(t), 24},
		{"v10-plain", linuxV10PlainHex, "v10", linuxBasicKey, linuxBasicKey, 23},
		{"v11-hashed", linuxV11HashedHex, "v11", keyringKey(t), keyringKey(t), 24},
		{"v11-plain", linuxV11PlainHex, "v11", keyringKey(t), keyringKey(t), 18},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			want := mustHex(t, c.blob)
			got, err := lnx.open(want, c.openKey, goldenHost, c.version)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if got != goldenValue {
				t.Fatalf("open = %q, want %q", got, goldenValue)
			}
			if sealed := linuxSealed(t, c.tag, c.sealKey, goldenValue, goldenHost, c.version); !bytes.Equal(sealed, want) {
				t.Fatalf("seal = %x, want %s", sealed, c.blob)
			}
		})
	}
}

func TestSchemeLinuxRoundTrip(t *testing.T) {
	values := []string{"", "plain-ascii-token", "café—naïve—日本語—😀", strings.Repeat("x", 16), strings.Repeat("v", 4096)}
	hosts := []HostKey{".example.com", "example.com"}
	tags := map[string]AesKey{"v10": linuxBasicKey, "v11": keyringKey(t)}
	for tag, key := range tags {
		for _, version := range []int{23, 24} {
			for _, host := range hosts {
				for _, value := range values {
					blob := linuxSealed(t, tag, key, value, host, version)
					if !bytes.HasPrefix(blob, []byte(tag)) {
						t.Fatalf("%s blob starts with %q", tag, blob[:3])
					}
					got, err := lnx.open(blob, keyringKey(t), host, version)
					if err != nil {
						t.Fatalf("%s/%d/%s/%q: open: %v", tag, version, host, value, err)
					}
					if got != value {
						t.Fatalf("%s/%d/%s: roundtrip = %q, want %q", tag, version, host, got, value)
					}
				}
			}
		}
	}
}

func TestSchemeLinuxV11NeedsKeyringKey(t *testing.T) {
	blob := mustHex(t, linuxV11HashedHex)
	_, err := lnx.open(blob, linuxBasicKey, goldenHost, 24)
	if !errors.Is(err, ErrV11KeyUnavailable) {
		t.Fatalf("v11 under the basic key: got %v, want ErrV11KeyUnavailable", err)
	}
	var de *DecryptError
	if errors.As(err, &de) {
		t.Fatalf("a missing v11 key must not be an ordinary per-row DecryptError: %v", err)
	}
	_, err = lnx.open(blob, otherKeyringKey(t), goldenHost, 24)
	if !errors.As(err, &de) {
		t.Fatalf("v11 under the wrong keyring key must be a per-row DecryptError, got %T: %v", err, err)
	}
}

func TestSchemeLinuxUnsupportedPrefixes(t *testing.T) {
	cases := []struct {
		id       string
		blob     []byte
		mentions string
		hides    string
	}{
		{"v12-portal", append([]byte("v12"), bytes.Repeat([]byte{0x01}, 28)...), "v12", ""},
		{"v20-app-bound", append([]byte("v20"), bytes.Repeat([]byte{0x00}, 32)...), "v20", ""},
		{"unversioned", []byte("secret-plain-value"), "unversioned", "sec"},
		{"empty", nil, "unversioned", ""},
		{"short", []byte("v1"), "unversioned", ""},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			_, err := lnx.open(c.blob, keyringKey(t), goldenHost, 24)
			if !errors.Is(err, ErrUnsupportedPrefix) {
				t.Fatalf("got %v, want ErrUnsupportedPrefix", err)
			}
			if errors.Is(err, ErrV20) {
				t.Fatalf("Linux never reports ErrV20: %v", err)
			}
			if !strings.Contains(err.Error(), c.mentions) {
				t.Fatalf("error %q does not mention %q", err, c.mentions)
			}
			if c.hides != "" && strings.Contains(err.Error(), c.hides) {
				t.Fatalf("error %q leaks value bytes", err)
			}
		})
	}
}

func TestSchemeLinuxStoreVersionDecidesHashPrefix(t *testing.T) {
	hashed := linuxSealed(t, "v10", linuxBasicKey, goldenValue, goldenHost, 24)
	plain := linuxSealed(t, "v10", linuxBasicKey, goldenValue, goldenHost, 23)
	if len(hashed) != len(plain)+domainHashLength {
		t.Fatalf("hashed blob is %d bytes, plain %d; want a %d-byte difference", len(hashed), len(plain), domainHashLength)
	}
	_, err := lnx.open(plain, linuxBasicKey, goldenHost, 24)
	var de *DecryptError
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "domain-hash prefix mismatch") {
		t.Fatalf("plain blob read as hashed: got %v, want a domain-hash mismatch", err)
	}
	if got, err := lnx.open(hashed, linuxBasicKey, goldenHost, 23); err == nil && got == goldenValue {
		t.Fatal("hashed blob read as plain must not yield the bare value")
	}
}

func TestSchemeLinuxHostKeyHashIsExact(t *testing.T) {
	cases := []struct {
		id     string
		sealed HostKey
		opened HostKey
		ok     bool
	}{
		{"same-dotted", ".example.com", ".example.com", true},
		{"same-bare", "example.com", "example.com", true},
		{"dotted-blob-bare-host", ".example.com", "example.com", false},
		{"bare-blob-dotted-host", "example.com", ".example.com", false},
		{"other-host", ".example.com", ".other.com", false},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			blob := linuxSealed(t, "v11", keyringKey(t), goldenValue, c.sealed, 24)
			got, err := lnx.open(blob, keyringKey(t), c.opened, 24)
			if c.ok {
				if err != nil || got != goldenValue {
					t.Fatalf("open = %q, %v; want %q", got, err, goldenValue)
				}
				return
			}
			var de *DecryptError
			if !errors.As(err, &de) || !strings.Contains(err.Error(), "wrong key") {
				t.Fatalf("got %v, want a domain-hash mismatch DecryptError", err)
			}
		})
	}
}

func TestSchemeDecryptRowsClassification(t *testing.T) {
	row := func(name string, blob []byte) EncryptedRow {
		return EncryptedRow{HostKey: goldenHost, Name: name, EncryptedValue: blob, Path: "/", metaVersion: 24}
	}
	v10 := row("basic", linuxSealed(t, "v10", linuxBasicKey, "one", goldenHost, 24))
	v11 := row("keyring", linuxSealed(t, "v11", keyringKey(t), "two", goldenHost, 24))
	v11Other := row("stale", linuxSealed(t, "v11", otherKeyringKey(t), "three", goldenHost, 24))
	v20 := row("bound", append([]byte("v20"), bytes.Repeat([]byte{0x00}, 32)...))
	darwinV10 := row("mac", mustHex(t, goldenBlobHex))

	cases := []struct {
		id        string
		codec     codec
		rows      []EncryptedRow
		key       AesKey
		want      []string
		counts    DecryptCounts
		wantErr   error
		errIsNone bool
	}{
		{id: "linux-keyring-key", codec: linuxCodec, rows: []EncryptedRow{v10, v11, v11Other}, key: keyringKey(t), want: []string{"one", "two"}, counts: DecryptCounts{Failed: 1}, errIsNone: true},
		{id: "linux-basic-key-only-v10", codec: linuxCodec, rows: []EncryptedRow{v10}, key: linuxBasicKey, want: []string{"one"}, errIsNone: true},
		{id: "linux-basic-key-meets-v11", codec: linuxCodec, rows: []EncryptedRow{v10, v11}, key: linuxBasicKey, wantErr: ErrV11KeyUnavailable},
		{id: "linux-v20", codec: linuxCodec, rows: []EncryptedRow{v10, v20}, key: keyringKey(t), wantErr: ErrUnsupportedPrefix},
		{id: "darwin-v20-counted", codec: darwinCodec, rows: []EncryptedRow{darwinV10, v20, v11}, key: mac.deriveKey(SafeStorageKey("peanuts")), want: []string{goldenValue}, counts: DecryptCounts{V20: 1, Failed: 1}, errIsNone: true},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			cookies, counts, err := c.codec.decryptRows(c.rows, c.key)
			if c.errIsNone && err != nil {
				t.Fatalf("decryptRows: %v", err)
			}
			if !c.errIsNone {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("got %v, want %v", err, c.wantErr)
				}
				if cookies != nil {
					t.Fatalf("a store-level failure must return no cookies, got %d", len(cookies))
				}
				return
			}
			if counts != c.counts {
				t.Fatalf("counts = %+v, want %+v", counts, c.counts)
			}
			var got []string
			for _, cookie := range cookies {
				got = append(got, cookie.Value)
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("values = %v, want %v", got, c.want)
			}
		})
	}
}
