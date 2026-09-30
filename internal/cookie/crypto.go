package cookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // Chrome's Safe Storage KDF is fixed at PBKDF2-HMAC-SHA1; parity, not a security choice.
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keyLength          = 16
	tagLength          = 3
	domainHashLength   = sha256.Size
	hashedStoreVersion = 24
)

var (
	salt = []byte("saltysalt")
	iv   = bytes.Repeat([]byte{0x20}, 16)
)

// ErrV20 marks a v20 (app-bound) cookie value, which cannot be decrypted with the
// Safe Storage key. The pipeline counts these separately from other decrypt
// failures, so callers branch on it with errors.Is(err, ErrV20).
var ErrV20 = errors.New("v20 app-bound cookie (not decryptable with the Safe Storage key)")

// ErrV11KeyUnavailable marks a v11 (keyring-encrypted) cookie value met on a host
// that holds only the basic-store key. It fails the whole read rather than dropping
// the row, so a keyring-backed profile is never silently reported as smaller than
// it is.
var ErrV11KeyUnavailable = errors.New("v11 cookie needs the Secret Service Safe Storage key; this host holds only the basic-store key")

// ErrUnsupportedPrefix marks a cookie value whose encryption tag this host cannot
// decrypt at all: v12 (portal-bound), v20 (app-bound) on Linux, or an unversioned
// value. It fails the whole read.
var ErrUnsupportedPrefix = errors.New("unsupported cookie encryption prefix")

// ErrStoreTagUnknown refuses a write into a store with no encrypted rows: the tag
// the owning browser encrypts with cannot be determined, so nothing is written
// rather than guessing a weaker one.
var ErrStoreTagUnknown = errors.New("cookie store has no encrypted rows to determine its encryption tag from")

// ErrStoreTagUnmatched refuses a write into a store holding rows under a tag this
// host cannot produce (v12 or unknown), since the write could not match what the
// browser expects.
var ErrStoreTagUnmatched = errors.New("cookie store holds encryption tags this host cannot match")

// ErrStoreKeyMismatch refuses a v11 write when the key in hand decrypts none of the
// store's existing v11 rows: writing under the wrong keyring secret would make the
// browser discard those cookies on load.
var ErrStoreKeyMismatch = errors.New("the Safe Storage key in hand decrypts none of the cookie store's v11 rows")

// ErrStoreVersionUnknown refuses I/O against a store whose meta.version cannot be
// read, since it decides whether values carry the host_key hash prefix.
var ErrStoreVersionUnknown = errors.New("cookie store meta.version is unreadable")

// DecryptError reports that a cookie value could not be decrypted: a v20 app-bound
// blob, a malformed ciphertext, or a wrong key. Its message mirrors the Python
// implementation byte-for-byte.
type DecryptError struct {
	Msg string
	Err error
}

func (e *DecryptError) Error() string { return e.Msg }

func (e *DecryptError) Unwrap() error { return e.Err }

func pbkdf2Key(password []byte, iterations int) AesKey {
	return AesKey(pbkdf2.Key(password, salt, iterations, keyLength, sha1.New))
}

func pkcs7Pad(data []byte) []byte {
	pad := 16 - len(data)%16
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, &DecryptError{Msg: "empty plaintext"}
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > 16 || pad > len(data) {
		return nil, &DecryptError{Msg: fmt.Sprintf("bad PKCS7 padding length %d", pad)}
	}
	if !bytes.Equal(data[len(data)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, &DecryptError{Msg: "inconsistent PKCS7 padding"}
	}
	return data[:len(data)-pad], nil
}

func domainHash(hostKey HostKey) []byte {
	sum := sha256.Sum256([]byte(hostKey))
	return sum[:]
}

func splitTag(encrypted []byte) (string, []byte) {
	if len(encrypted) < tagLength {
		return string(encrypted), nil
	}
	return string(encrypted[:tagLength]), encrypted[tagLength:]
}

func openCBC(ciphertext []byte, key AesKey) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, &DecryptError{Msg: "ciphertext is not a positive multiple of the block size"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return pkcs7Unpad(plain)
}

func sealCBC(tag string, plain []byte, key AesKey) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	padded := pkcs7Pad(plain)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded) //nolint:gosec // G407: Chromium's os_crypt fixes the CBC IV at 16 spaces.
	return append([]byte(tag), out...), nil
}
