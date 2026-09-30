package cookie

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var samesitePlaywright = map[string]int{"None": 0, "Lax": 1, "Strict": 2}

type renderedCookie struct {
	Name     *string         `json:"name"`
	Value    *string         `json:"value"`
	Domain   *string         `json:"domain"`
	Path     *string         `json:"path"`
	Expires  json.RawMessage `json:"expires"`
	HTTPOnly *bool           `json:"httpOnly"`
	Secure   *bool           `json:"secure"`
	SameSite *string         `json:"sameSite"`
}

type renderedEntry struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
}

type playwrightOrigin struct {
	Origin       *string          `json:"origin"`
	LocalStorage *[]renderedEntry `json:"localStorage"`
}

type webStorageOrigin struct {
	Origin         *string          `json:"origin"`
	LocalStorage   *[]renderedEntry `json:"localStorage"`
	SessionStorage *[]renderedEntry `json:"sessionStorage"`
}

type playwrightDocument struct {
	Cookies *[]renderedCookie   `json:"cookies"`
	Origins *[]playwrightOrigin `json:"origins"`
}

type webStorageDocument struct {
	Origins *[]webStorageOrigin `json:"origins"`
}

type presence struct {
	key     string
	present bool
}

func (c renderedCookie) model(index int) (Cookie, error) {
	if key, ok := firstMissing(
		presence{"name", c.Name != nil},
		presence{"value", c.Value != nil},
		presence{"domain", c.Domain != nil},
		presence{"path", c.Path != nil},
		presence{"expires", len(c.Expires) > 0},
		presence{"httpOnly", c.HTTPOnly != nil},
		presence{"secure", c.Secure != nil},
		presence{"sameSite", c.SameSite != nil},
	); ok {
		return Cookie{}, fmt.Errorf("cookies[%d] missing %q", index, key)
	}
	if !strings.HasPrefix(*c.Path, "/") {
		return Cookie{}, fmt.Errorf("cookies[%d] path must start with /", index)
	}
	sameSite, ok := samesitePlaywright[*c.SameSite]
	if !ok {
		return Cookie{}, fmt.Errorf("cookies[%d] sameSite is not None, Lax, or Strict", index)
	}
	if sameSite == 0 && !*c.Secure {
		return Cookie{}, fmt.Errorf("cookies[%d] is sameSite None without secure", index)
	}
	expires, ok := renderedExpiry(c.Expires)
	if !ok {
		return Cookie{}, fmt.Errorf("cookies[%d] expires is neither -1 nor a positive Unix time", index)
	}
	return Cookie{
		HostKey:    HostKey(*c.Domain),
		Name:       *c.Name,
		Value:      *c.Value,
		Path:       *c.Path,
		ExpiresUTC: expires,
		IsSecure:   *c.Secure,
		IsHTTPOnly: *c.HTTPOnly,
		SameSite:   sameSite,
	}, nil
}

func (o playwrightOrigin) model(index int) (OriginStorage, error) {
	if key, ok := firstMissing(
		presence{"origin", o.Origin != nil},
		presence{"localStorage", o.LocalStorage != nil},
	); ok {
		return OriginStorage{}, fmt.Errorf("origins[%d] missing %q", index, key)
	}
	if len(*o.LocalStorage) == 0 {
		return OriginStorage{}, fmt.Errorf("origins[%d] carries no localStorage", index)
	}
	local, err := storageEntries(*o.LocalStorage, index, "localStorage")
	if err != nil {
		return OriginStorage{}, err
	}
	return OriginStorage{Origin: *o.Origin, LocalStorage: local}, nil
}

func (o webStorageOrigin) model(index int) (OriginStorage, error) {
	if key, ok := firstMissing(
		presence{"origin", o.Origin != nil},
		presence{"localStorage", o.LocalStorage != nil},
		presence{"sessionStorage", o.SessionStorage != nil},
	); ok {
		return OriginStorage{}, fmt.Errorf("origins[%d] missing %q", index, key)
	}
	local, err := storageEntries(*o.LocalStorage, index, "localStorage")
	if err != nil {
		return OriginStorage{}, err
	}
	session, err := storageEntries(*o.SessionStorage, index, "sessionStorage")
	if err != nil {
		return OriginStorage{}, err
	}
	return OriginStorage{Origin: *o.Origin, LocalStorage: local, SessionStorage: session}, nil
}

// ParseRendered parses one document Render emitted in format (FormatPlaywright or
// FormatWebStorage) back into the StorageState it was rendered from, refusing anything
// outside Render's image.
func ParseRendered(data []byte, format OutputFormat) (StorageState, error) {
	var (
		state StorageState
		err   error
	)
	switch format {
	case FormatPlaywright:
		state, err = parsePlaywright(data)
	case FormatWebStorage:
		state, err = parseWebStorage(data)
	default:
		return StorageState{}, fmt.Errorf("cannot parse a %s document", format)
	}
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
	)
	switch {
	case errors.As(err, &syntaxErr):
		return StorageState{}, fmt.Errorf("parse %s document: invalid JSON at offset %d", format, syntaxErr.Offset)
	case errors.As(err, &typeErr):
		return StorageState{}, fmt.Errorf("parse %s document: wrong JSON type at offset %d", format, typeErr.Offset)
	case err != nil:
		return StorageState{}, fmt.Errorf("parse %s document: %w", format, err)
	}
	return state, nil
}

func parsePlaywright(data []byte) (StorageState, error) {
	var doc playwrightDocument
	if err := decodeWire(data, &doc); err != nil {
		return StorageState{}, err
	}
	if key, ok := firstMissing(
		presence{"cookies", doc.Cookies != nil},
		presence{"origins", doc.Origins != nil},
	); ok {
		return StorageState{}, fmt.Errorf("missing %q", key)
	}
	cookies := make([]Cookie, len(*doc.Cookies))
	for i, rendered := range *doc.Cookies {
		c, err := rendered.model(i)
		if err != nil {
			return StorageState{}, err
		}
		cookies[i] = c
	}
	origins := make([]OriginStorage, len(*doc.Origins))
	for i, rendered := range *doc.Origins {
		o, err := rendered.model(i)
		if err != nil {
			return StorageState{}, err
		}
		origins[i] = o
	}
	return StorageState{Cookies: cookies, Origins: origins}, nil
}

func parseWebStorage(data []byte) (StorageState, error) {
	var doc webStorageDocument
	if err := decodeWire(data, &doc); err != nil {
		return StorageState{}, err
	}
	if doc.Origins == nil {
		return StorageState{}, errors.New(`missing "origins"`)
	}
	origins := make([]OriginStorage, len(*doc.Origins))
	for i, rendered := range *doc.Origins {
		o, err := rendered.model(i)
		if err != nil {
			return StorageState{}, err
		}
		origins[i] = o
	}
	return StorageState{Origins: origins}, nil
}

func storageEntries(rendered []renderedEntry, origin int, area string) ([]WebStorageEntry, error) {
	entries := make([]WebStorageEntry, len(rendered))
	for i, e := range rendered {
		if key, ok := firstMissing(
			presence{"name", e.Name != nil},
			presence{"value", e.Value != nil},
		); ok {
			return nil, fmt.Errorf("origins[%d].%s[%d] missing %q", origin, area, i, key)
		}
		entries[i] = WebStorageEntry{Name: *e.Name, Value: *e.Value}
	}
	return entries, nil
}

func renderedExpiry(raw json.RawMessage) (ChromeMicros, bool) {
	if string(raw) == "-1" {
		return 0, true
	}
	seconds, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	micros := roundedChromeMicros(seconds)
	if !micros.IsInt64() {
		return 0, false
	}
	return ChromeMicros(micros.Int64()), true
}

func firstMissing(fields ...presence) (string, bool) {
	for _, f := range fields {
		if !f.present {
			return f.key, true
		}
	}
	return "", false
}
