package cookie

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ProtocolVersion is the only cookie-owned wire epoch this binary accepts.
const ProtocolVersion = 1

// WireCookie is the newline-free JSON wire shape a Cookie crosses the rpc boundary as.
//
// The field names and order are the exact v1 contract the ssh peer protocol and the
// agent-browser skill depend on: host_key, name, value, path, expires_utc,
// last_update_utc, creation_utc, is_secure, is_httponly, samesite, source_scheme,
// source_port, top_frame_site_key, has_cross_site_ancestor. The model Cookie carries
// branded field types; WireCookie is the plain-typed projection used only at the
// boundary, keeping the JSON key order independent of the model's Go field order.
type WireCookie struct {
	HostKey              string       `json:"host_key"`
	Name                 string       `json:"name"`
	Value                string       `json:"value"`
	Path                 string       `json:"path"`
	ExpiresUTC           ChromeMicros `json:"expires_utc"`
	LastUpdateUTC        ChromeMicros `json:"last_update_utc"`
	CreationUTC          ChromeMicros `json:"creation_utc"`
	IsSecure             bool         `json:"is_secure"`
	IsHTTPOnly           bool         `json:"is_httponly"`
	SameSite             int          `json:"samesite"`
	SourceScheme         int          `json:"source_scheme"`
	SourcePort           int          `json:"source_port"`
	TopFrameSiteKey      string       `json:"top_frame_site_key"`
	HasCrossSiteAncestor int          `json:"has_cross_site_ancestor"`
}

// ToWire projects a Cookie into its wire shape.
func ToWire(c Cookie) WireCookie {
	return WireCookie{
		HostKey:              string(c.HostKey),
		Name:                 c.Name,
		Value:                c.Value,
		Path:                 c.Path,
		ExpiresUTC:           c.ExpiresUTC,
		LastUpdateUTC:        c.LastUpdateUTC,
		CreationUTC:          c.CreationUTC,
		IsSecure:             c.IsSecure,
		IsHTTPOnly:           c.IsHTTPOnly,
		SameSite:             c.SameSite,
		SourceScheme:         c.SourceScheme,
		SourcePort:           c.SourcePort,
		TopFrameSiteKey:      c.TopFrameSiteKey,
		HasCrossSiteAncestor: c.HasCrossSiteAncestor,
	}
}

// FromWire rebuilds a Cookie from its wire shape, re-branding the primitive
// fields.
func FromWire(w WireCookie) Cookie {
	return Cookie{
		HostKey:              HostKey(w.HostKey),
		Name:                 w.Name,
		Value:                w.Value,
		Path:                 w.Path,
		ExpiresUTC:           w.ExpiresUTC,
		LastUpdateUTC:        w.LastUpdateUTC,
		CreationUTC:          w.CreationUTC,
		IsSecure:             w.IsSecure,
		IsHTTPOnly:           w.IsHTTPOnly,
		SameSite:             w.SameSite,
		SourceScheme:         w.SourceScheme,
		SourcePort:           w.SourcePort,
		TopFrameSiteKey:      w.TopFrameSiteKey,
		HasCrossSiteAncestor: w.HasCrossSiteAncestor,
	}
}

// Envelope is the exact v1 cookie-set wire envelope.
type Envelope struct {
	ProtocolVersion uint64       `json:"protocol_version"`
	Cookies         []WireCookie `json:"cookies"`
}

// MarshalCookies encodes a cookie set in the exact v1 wire envelope.
func MarshalCookies(cookies []Cookie) ([]byte, error) {
	wire := make([]WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = ToWire(c)
	}
	return json.Marshal(Envelope{ProtocolVersion: ProtocolVersion, Cookies: wire})
}

// UnmarshalCookies decodes the exact v1 cookie-set envelope.
func UnmarshalCookies(data []byte) ([]Cookie, error) {
	var envelope Envelope
	if err := decodeWire(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("cookie protocol version %d, want %d", envelope.ProtocolVersion, ProtocolVersion)
	}
	if envelope.Cookies == nil {
		return nil, fmt.Errorf("cookie protocol v1 requires cookies array")
	}
	cookies := make([]Cookie, len(envelope.Cookies))
	for i, w := range envelope.Cookies {
		cookies[i] = FromWire(w)
	}
	return cookies, nil
}

// WireStorageEntry is the wire shape of one web-storage item: a name/value pair.
type WireStorageEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// WireOrigin is the wire shape of one origin's web storage. It is a SEPARATE top-level
// payload from WireCookie — origins never nest inside a cookie object — carried under the
// "origins" key of the get_web_storage contract.
type WireOrigin struct {
	Origin         string             `json:"origin"`
	LocalStorage   []WireStorageEntry `json:"localStorage"`
	SessionStorage []WireStorageEntry `json:"sessionStorage"`
}

// OriginEnvelope is the exact v1 web-storage wire envelope.
type OriginEnvelope struct {
	ProtocolVersion uint64       `json:"protocol_version"`
	Origins         []WireOrigin `json:"origins"`
}

func storageEntriesToWire(entries []WebStorageEntry) []WireStorageEntry {
	wire := make([]WireStorageEntry, len(entries))
	for i, e := range entries {
		wire[i] = WireStorageEntry(e)
	}
	return wire
}

func storageEntriesFromWire(wire []WireStorageEntry) []WebStorageEntry {
	entries := make([]WebStorageEntry, len(wire))
	for i, w := range wire {
		entries[i] = WebStorageEntry(w)
	}
	return entries
}

// OriginToWire projects an OriginStorage into its wire shape.
func OriginToWire(o OriginStorage) WireOrigin {
	return WireOrigin{
		Origin:         o.Origin,
		LocalStorage:   storageEntriesToWire(o.LocalStorage),
		SessionStorage: storageEntriesToWire(o.SessionStorage),
	}
}

// OriginFromWire rebuilds an OriginStorage from its wire shape.
func OriginFromWire(w WireOrigin) OriginStorage {
	return OriginStorage{
		Origin:         w.Origin,
		LocalStorage:   storageEntriesFromWire(w.LocalStorage),
		SessionStorage: storageEntriesFromWire(w.SessionStorage),
	}
}

// MarshalOrigins encodes an origin set in the exact v1 wire envelope.
func MarshalOrigins(origins []OriginStorage) ([]byte, error) {
	wire := make([]WireOrigin, len(origins))
	for i, o := range origins {
		wire[i] = OriginToWire(o)
	}
	return json.Marshal(OriginEnvelope{ProtocolVersion: ProtocolVersion, Origins: wire})
}

// UnmarshalOrigins decodes the exact v1 web-storage envelope.
func UnmarshalOrigins(data []byte) ([]OriginStorage, error) {
	var envelope OriginEnvelope
	if err := decodeWire(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("origin protocol version %d, want %d", envelope.ProtocolVersion, ProtocolVersion)
	}
	if envelope.Origins == nil {
		return nil, fmt.Errorf("origin protocol v1 requires origins array")
	}
	origins := make([]OriginStorage, len(envelope.Origins))
	for i, w := range envelope.Origins {
		origins[i] = OriginFromWire(w)
	}
	return origins, nil
}

func decodeWire(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("cookie wire carries trailing JSON")
	}
	return nil
}
