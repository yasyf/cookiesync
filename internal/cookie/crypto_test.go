package cookie

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Parity oracles ported byte-for-byte from the original Python tests/cookie/test_crypto.py.
// derive_key("peanuts") over value "hello-session-token" at host_key ".example.com".
// Locking the exact bytes pins the PBKDF2 params, the fixed IV, the domain-hash
// prefix, and PKCS7 padding.
const (
	goldenKeyHex  = "d9a09d499b4e1b7461f28e67972c6dbd"
	goldenHost    = HostKey(".example.com")
	goldenValue   = "hello-session-token"
	goldenBlobHex = "763130bfd1db3abcef87f1fa5a40b21d11eaaa9a030da41e8699c59583ed42e9" +
		"4a5d1c649d73f94aeb15d5dcd9947b962e805181247a0bdd90291dd8ced1eb01e89451"
)

func key(t *testing.T) AesKey {
	t.Helper()
	return DeriveKey(SafeStorageKey("peanuts"))
}

func otherKey(t *testing.T) AesKey {
	t.Helper()
	return DeriveKey(SafeStorageKey("almonds"))
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestDeriveKeyIsDeterministic16Bytes(t *testing.T) {
	got := key(t)
	if want := mustHex(t, goldenKeyHex); !bytes.Equal(got, want) {
		t.Fatalf("DeriveKey(peanuts) = %x, want %s", got, goldenKeyHex)
	}
	if len(got) != 16 {
		t.Fatalf("key length = %d, want 16", len(got))
	}
}

func TestGoldenVectorDecrypts(t *testing.T) {
	blob := mustHex(t, goldenBlobHex)
	if !bytes.HasPrefix(blob, []byte("v10")) {
		t.Fatalf("golden blob does not start with v10")
	}
	got, err := DecryptValue(blob, key(t), goldenHost)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if got != goldenValue {
		t.Fatalf("DecryptValue = %q, want %q", got, goldenValue)
	}
}

func TestGoldenVectorEncryptsToExactBytes(t *testing.T) {
	got, err := EncryptValue(goldenValue, key(t), goldenHost)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	if want := mustHex(t, goldenBlobHex); !bytes.Equal(got, want) {
		t.Fatalf("EncryptValue = %x, want %s", got, goldenBlobHex)
	}
}

func TestRoundtrip(t *testing.T) {
	values := []struct {
		id    string
		value string
	}{
		{"ascii", "plain-ascii-token"},
		{"utf8-multibyte", "café—naïve—日本語—😀"},
		{"empty", ""},
		{"16-byte-boundary", strings.Repeat("x", 16)},
		{"15-byte", strings.Repeat("y", 15)},
		{"17-byte", strings.Repeat("z", 17)},
		{"long", "a=1; b=2; long-" + strings.Repeat("v", 4096)},
	}
	hosts := []struct {
		id   string
		host HostKey
	}{
		{"dot-host", HostKey(".example.com")},
		{"bare-host", HostKey("example.com")},
	}
	for _, h := range hosts {
		for _, v := range values {
			t.Run(h.id+"/"+v.id, func(t *testing.T) {
				blob, err := EncryptValue(v.value, key(t), h.host)
				if err != nil {
					t.Fatalf("EncryptValue: %v", err)
				}
				got, err := DecryptValue(blob, key(t), h.host)
				if err != nil {
					t.Fatalf("DecryptValue: %v", err)
				}
				if got != v.value {
					t.Fatalf("roundtrip = %q, want %q", got, v.value)
				}
			})
		}
	}
}

func TestEmptyBlobIsRejected(t *testing.T) {
	if _, err := DecryptValue(nil, key(t), goldenHost); err == nil {
		t.Fatal("empty encrypted_value must not be accepted")
	}
}

func TestV20IsRejected(t *testing.T) {
	blob := append([]byte("v20"), bytes.Repeat([]byte{0x00}, 32)...)
	_, err := DecryptValue(blob, key(t), goldenHost)
	if err == nil {
		t.Fatal("expected DecryptError, got nil")
	}
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("error is not *DecryptError: %T", err)
	}
	if !errors.Is(err, ErrV20) {
		t.Fatalf("v20 blob does not unwrap to ErrV20: %v", err)
	}
	if !strings.Contains(err.Error(), "v20") {
		t.Fatalf("error %q does not mention v20", err)
	}
}

func TestWrongKeyRaisesNoSilentGarbage(t *testing.T) {
	// A wrong AES key garbles the whole block: it must raise (bad padding or a
	// domain-hash mismatch), never return decoded garbage.
	blob, err := EncryptValue("secret", key(t), goldenHost)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	_, err = DecryptValue(blob, otherKey(t), goldenHost)
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DecryptError, got %T: %v", err, err)
	}
}

func TestWrongHostKeyRaises(t *testing.T) {
	// The domain hash commits to the exact host_key, so decrypting under a
	// different host (with the right AES key) must fail on the hash check, not
	// silently strip 32 bytes and return the wrong tail.
	blob, err := EncryptValue("secret", key(t), goldenHost)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	_, err = DecryptValue(blob, key(t), HostKey(".other.com"))
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DecryptError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("error %q does not mention wrong key", err)
	}
}

func TestNonBlockAlignedCiphertextRaises(t *testing.T) {
	blob := append([]byte("v10"), bytes.Repeat([]byte{0x00}, 17)...)
	_, err := DecryptValue(blob, key(t), goldenHost)
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DecryptError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "block size") {
		t.Fatalf("error %q does not mention block size", err)
	}
}

func TestPKCS7PadUnpadInverseOverAllRemainders(t *testing.T) {
	for size := 0; size <= 32; size++ {
		data := bytes.Repeat([]byte{0xab}, size)
		padded := pkcs7Pad(data)
		if len(padded)%16 != 0 {
			t.Fatalf("size %d: padded length %d not a multiple of 16", size, len(padded))
		}
		if len(padded) <= len(data) {
			t.Fatalf("size %d: padded length %d not greater than %d", size, len(padded), len(data))
		}
		got, err := pkcs7Unpad(padded)
		if err != nil {
			t.Fatalf("size %d: pkcs7Unpad: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: unpad = %x, want %x", size, got, data)
		}
	}
}

func TestPKCS7PadFullBlockAddsFullBlock(t *testing.T) {
	got := pkcs7Pad(bytes.Repeat([]byte{0x00}, 16))
	want := append(bytes.Repeat([]byte{0x00}, 16), bytes.Repeat([]byte{16}, 16)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("pkcs7Pad(16x0) = %x, want %x", got, want)
	}
}

func TestPKCS7UnpadRejectsBadPadding(t *testing.T) {
	cases := []struct {
		id  string
		bad []byte
	}{
		{"empty", []byte{}},
		{"zero-pad-byte", []byte{0xab, 0x00}},
		{"pad-exceeds-length", []byte{0x01, 0x02, 0x03, 0x05}},
		{"inconsistent-pad", []byte{0xab, 0xab, 0x02, 0x03}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			_, err := pkcs7Unpad(c.bad)
			var de *DecryptError
			if !errors.As(err, &de) {
				t.Fatalf("expected *DecryptError, got %T: %v", err, err)
			}
		})
	}
}

func TestUnprefixedPlaintextBlobIsRejected(t *testing.T) {
	if _, err := DecryptValue([]byte("legacy-plain-value"), AesKey(bytes.Repeat([]byte{0x00}, 16)), goldenHost); err == nil {
		t.Fatal("unprefixed encrypted_value must not be accepted")
	}
}

func TestDomainHashDualAcceptIsAsymmetric(t *testing.T) {
	// The domain-hash dual-accept (computed both with the passed host_key as-is and
	// with its leading dot stripped) is asymmetric, matching the Python oracle:
	// the candidate set derives from the *passed* host, while encrypt commits the
	// hash of the host AS-IS. So a blob committed under bare "example.com" decrypts
	// when the caller passes dotted ".example.com" (strip-the-dot candidate hits),
	// but a blob committed under ".example.com" does NOT decrypt under bare
	// "example.com" — neither candidate reproduces SHA256(".example.com").
	bareBlob, err := EncryptValue(goldenValue, key(t), HostKey("example.com"))
	if err != nil {
		t.Fatalf("EncryptValue bare: %v", err)
	}
	got, err := DecryptValue(bareBlob, key(t), HostKey(".example.com"))
	if err != nil {
		t.Fatalf("DecryptValue dotted host on bare blob: %v", err)
	}
	if got != goldenValue {
		t.Fatalf("bare-blob/dotted-host = %q, want %q", got, goldenValue)
	}

	dotBlob, err := EncryptValue(goldenValue, key(t), HostKey(".example.com"))
	if err != nil {
		t.Fatalf("EncryptValue dotted: %v", err)
	}
	_, err = DecryptValue(dotBlob, key(t), HostKey("example.com"))
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("dotted-blob/bare-host: expected *DecryptError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("dotted-blob/bare-host error %q does not mention wrong key", err)
	}
}
