package cookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // Chrome's Safe Storage KDF is fixed at PBKDF2-HMAC-SHA1; parity, not a security choice.
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

// Chrome macOS "Safe Storage" v10 crypto parameters. These are fixed by Chrome and
// must match byte-for-byte:
//
//	key   = PBKDF2-HMAC-SHA1(safe_storage_password, "saltysalt", 1003, dklen=16)
//	value = AES-128-CBC(key, iv=16x 0x20) over the ciphertext, PKCS7-(un)padded, with
//	        a 32-byte SHA256(host_key) domain-hash prefix Chrome v24+ prepends.
const (
	iterations = 1003
	keyLength  = 16
)

var (
	salt = []byte("saltysalt")
	iv   = bytes.Repeat([]byte{0x20}, 16)
)

// ErrV20 marks a v20 (app-bound) cookie value, which cannot be decrypted with the
// Safe Storage key. The pipeline counts these separately from other decrypt
// failures, so callers branch on it with errors.Is(err, ErrV20).
var ErrV20 = errors.New("v20 app-bound cookie (not decryptable with the Safe Storage key)")

// DecryptError reports that a cookie value could not be decrypted: a v20 app-bound
// blob, a malformed ciphertext, or a wrong key. Its message mirrors the Python
// implementation byte-for-byte.
type DecryptError struct {
	Msg string
	Err error
}

func (e *DecryptError) Error() string { return e.Msg }

func (e *DecryptError) Unwrap() error { return e.Err }

// DeriveKey derives the 16-byte AES key from the raw "Safe Storage" password.
func DeriveKey(password SafeStorageKey) AesKey {
	return AesKey(pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha1.New))
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

// DecryptValue decrypts one canonical Chrome v10 encrypted_value blob. It returns a
// *DecryptError on any failure; a v20 blob unwraps to ErrV20.
func DecryptValue(encrypted []byte, key AesKey, hostKey HostKey) (string, error) {
	var ciphertext []byte
	switch {
	case bytes.HasPrefix(encrypted, []byte("v20")):
		return "", &DecryptError{Msg: ErrV20.Error(), Err: ErrV20}
	case bytes.HasPrefix(encrypted, []byte("v10")):
		ciphertext = encrypted[3:]
	default:
		return "", &DecryptError{Msg: "unrecognized cookie encoding"}
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", &DecryptError{Msg: "ciphertext is not a positive multiple of the block size"}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)

	plain, err = pkcs7Unpad(plain)
	if err != nil {
		return "", err
	}

	if len(plain) < 32 || !domainHashMatches(plain[:32], hostKey) {
		return "", &DecryptError{Msg: "domain-hash prefix mismatch (wrong key)"}
	}

	value := plain[32:]
	if !utf8.Valid(value) {
		return "", &DecryptError{Msg: "decrypted value is not valid UTF-8 (likely wrong key)"}
	}
	return string(value), nil
}

// domainHashMatches dual-accepts the SHA256 of the host_key as stored and with its
// leading dot stripped, matching how Chrome commits either form.
func domainHashMatches(prefix []byte, hostKey HostKey) bool {
	return bytes.Equal(prefix, domainHash(hostKey)) ||
		bytes.Equal(prefix, domainHash(HostKey(strings.TrimLeft(string(hostKey), "."))))
}

// EncryptValue encrypts one cookie value into Chrome's v10 blob, committing to the
// exact host_key (leading dot included) via the 32-byte domain-hash prefix.
func EncryptValue(plaintext string, key AesKey, hostKey HostKey) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	padded := pkcs7Pad(append(domainHash(hostKey), plaintext...))
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return append([]byte("v10"), out...), nil
}
