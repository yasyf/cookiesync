package cookie

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	darwinIterations = 1003
	linuxIterations  = 1
	linuxBasicTag    = "v10"
	linuxKeyringTag  = "v11"
)

var linuxBasicKey = pbkdf2Key([]byte("peanuts"), linuxIterations)

type sealFunc func(value string, hostKey HostKey) ([]byte, error)

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// scheme is one platform's Chromium cookie value encryption: key derivation, the
// store's meta.version, opening one value, and choosing a write's tag and key.
type scheme interface {
	deriveKey(password SafeStorageKey) AesKey
	storeVersion(ctx context.Context, q rowQuerier) (int, error)
	open(encrypted []byte, key AesKey, hostKey HostKey, storeVersion int) (string, error)
	sealer(ctx context.Context, tx *sql.Tx, key AesKey) (sealFunc, error)
}

// codec binds the store pipeline to one scheme; hostCodec is the build-tagged pick.
type codec struct{ scheme }

var (
	darwinCodec = codec{darwinScheme{}}
	linuxCodec  = codec{linuxScheme{}}
)

// darwinScheme is Chrome's macOS Safe Storage v10 crypto: 1003 PBKDF2 iterations,
// an unconditional SHA-256(host_key) prefix that dual-accepts the dot-stripped host.
type darwinScheme struct{}

func (darwinScheme) deriveKey(password SafeStorageKey) AesKey {
	return pbkdf2Key([]byte(password), darwinIterations)
}

func (darwinScheme) storeVersion(context.Context, rowQuerier) (int, error) {
	return 0, nil
}

func (darwinScheme) open(encrypted []byte, key AesKey, hostKey HostKey, _ int) (string, error) {
	var ciphertext []byte
	switch {
	case bytes.HasPrefix(encrypted, []byte("v20")):
		return "", &DecryptError{Msg: ErrV20.Error(), Err: ErrV20}
	case bytes.HasPrefix(encrypted, []byte("v10")):
		ciphertext = encrypted[3:]
	default:
		return "", &DecryptError{Msg: "unrecognized cookie encoding"}
	}
	plain, err := openCBC(ciphertext, key)
	if err != nil {
		return "", err
	}
	if len(plain) < domainHashLength || !darwinDomainHashMatches(plain[:domainHashLength], hostKey) {
		return "", &DecryptError{Msg: "domain-hash prefix mismatch (wrong key)"}
	}
	return utf8Value(plain[domainHashLength:])
}

func darwinDomainHashMatches(prefix []byte, hostKey HostKey) bool {
	return bytes.Equal(prefix, domainHash(hostKey)) ||
		bytes.Equal(prefix, domainHash(HostKey(strings.TrimLeft(string(hostKey), "."))))
}

func (darwinScheme) sealer(_ context.Context, _ *sql.Tx, key AesKey) (sealFunc, error) {
	return func(value string, hostKey HostKey) ([]byte, error) {
		return sealCBC("v10", append(domainHash(hostKey), value...), key)
	}, nil
}

// linuxScheme is Chromium's Linux os_crypt: v10 under the fixed basic-store key,
// v11 under the Secret Service secret (1 PBKDF2 iteration each), the host_key hash
// prefix only from meta.version 24; v12 and unknown tags are unsupported.
type linuxScheme struct{}

func (linuxScheme) deriveKey(password SafeStorageKey) AesKey {
	return pbkdf2Key([]byte(password), linuxIterations)
}

func (linuxScheme) storeVersion(ctx context.Context, q rowQuerier) (int, error) {
	return metaVersion(ctx, q)
}

func metaVersion(ctx context.Context, q rowQuerier) (int, error) {
	var version int
	err := q.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'version'").Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrStoreVersionUnknown
	}
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrStoreVersionUnknown, err)
	}
	return version, nil
}

func linuxKeyringKey(key AesKey) (AesKey, bool) {
	if bytes.Equal(key, linuxBasicKey) {
		return nil, false
	}
	return key, true
}

func (s linuxScheme) open(encrypted []byte, key AesKey, hostKey HostKey, storeVersion int) (string, error) {
	tag, ciphertext := splitTag(encrypted)
	tagKey, err := s.tagKey(tag, key)
	if err != nil {
		return "", err
	}
	plain, err := openCBC(ciphertext, tagKey)
	if err != nil {
		return "", err
	}
	if storeVersion >= hashedStoreVersion {
		if len(plain) < domainHashLength || !bytes.Equal(plain[:domainHashLength], domainHash(hostKey)) {
			return "", &DecryptError{Msg: "domain-hash prefix mismatch (wrong key)"}
		}
		plain = plain[domainHashLength:]
	}
	return utf8Value(plain)
}

func (linuxScheme) tagKey(tag string, key AesKey) (AesKey, error) {
	switch tag {
	case linuxBasicTag:
		return linuxBasicKey, nil
	case linuxKeyringTag:
		keyring, ok := linuxKeyringKey(key)
		if !ok {
			return nil, ErrV11KeyUnavailable
		}
		return keyring, nil
	default:
		return nil, unsupportedPrefix(tag)
	}
}

func unsupportedPrefix(tag string) error {
	if len(tag) == tagLength && tag[0] == 'v' && isDigit(tag[1]) && isDigit(tag[2]) {
		return fmt.Errorf("%w: %s", ErrUnsupportedPrefix, tag)
	}
	return fmt.Errorf("%w: unversioned value", ErrUnsupportedPrefix)
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func (linuxScheme) seal(tag string, key AesKey, value string, hostKey HostKey, storeVersion int) ([]byte, error) {
	var plain []byte
	if storeVersion >= hashedStoreVersion {
		plain = domainHash(hostKey)
	}
	return sealCBC(tag, append(plain, value...), key)
}

type sealedRow struct {
	hostKey   HostKey
	encrypted []byte
}

func sealedRows(ctx context.Context, tx *sql.Tx) ([]sealedRow, error) {
	rows, err := tx.QueryContext(ctx, "SELECT host_key, encrypted_value FROM cookies WHERE length(encrypted_value) > 0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []sealedRow
	for rows.Next() {
		var row sealedRow
		if err := rows.Scan(&row.hostKey, &row.encrypted); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func linuxStoreTag(rows []sealedRow) (string, error) {
	if len(rows) == 0 {
		return "", ErrStoreTagUnknown
	}
	tag := linuxBasicTag
	for _, row := range rows {
		switch rowTag, _ := splitTag(row.encrypted); rowTag {
		case linuxBasicTag:
		case linuxKeyringTag:
			tag = linuxKeyringTag
		default:
			return "", fmt.Errorf("%w: %w", ErrStoreTagUnmatched, unsupportedPrefix(rowTag))
		}
	}
	return tag, nil
}

func (s linuxScheme) sealKey(tag string, key AesKey, rows []sealedRow, storeVersion int) (AesKey, error) {
	if tag == linuxBasicTag {
		return linuxBasicKey, nil
	}
	keyring, ok := linuxKeyringKey(key)
	if !ok {
		return nil, ErrV11KeyUnavailable
	}
	for _, row := range rows {
		if !bytes.HasPrefix(row.encrypted, []byte(linuxKeyringTag)) {
			continue
		}
		if _, err := s.open(row.encrypted, keyring, row.hostKey, storeVersion); err == nil {
			return keyring, nil
		}
	}
	return nil, ErrStoreKeyMismatch
}

func (s linuxScheme) sealer(ctx context.Context, tx *sql.Tx, key AesKey) (sealFunc, error) {
	storeVersion, err := metaVersion(ctx, tx)
	if err != nil {
		return nil, err
	}
	rows, err := sealedRows(ctx, tx)
	if err != nil {
		return nil, err
	}
	tag, err := linuxStoreTag(rows)
	if err != nil {
		return nil, err
	}
	sealKey, err := s.sealKey(tag, key, rows, storeVersion)
	if err != nil {
		return nil, err
	}
	return func(value string, hostKey HostKey) ([]byte, error) {
		return s.seal(tag, sealKey, value, hostKey, storeVersion)
	}, nil
}

func utf8Value(value []byte) (string, error) {
	if !utf8.Valid(value) {
		return "", &DecryptError{Msg: "decrypted value is not valid UTF-8 (likely wrong key)"}
	}
	return string(value), nil
}

// DeriveKey derives the 16-byte AES key from the raw Safe Storage password with this
// host's KDF parameters.
func DeriveKey(password SafeStorageKey) AesKey {
	return hostCodec.deriveKey(password)
}
