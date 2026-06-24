package cookie

import "encoding/json"

// WireCookie is the newline-free JSON wire shape a Cookie crosses the rpc boundary as.
//
// The field names and order are the FROZEN contract the ssh peer protocol and the
// agent-browser skill depend on: host_key, name, value, path, expires_utc,
// last_update_utc, creation_utc, is_secure, is_httponly, samesite, source_scheme,
// source_port, top_frame_site_key, has_cross_site_ancestor. It mirrors the Python
// dataclasses.asdict(Cookie) output byte-for-byte, so a Go daemon and a Python peer (or
// two Go daemons) interoperate. The model Cookie carries branded field types for the
// rest of the codebase; WireCookie is the plain-typed projection used only at the
// boundary, which keeps the JSON key order pinned independently of the model's Go field
// order.
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

// MarshalCookies encodes a cookie set as the {"cookies": [...]} payload the rpc
// extract contract emits, with each cookie in the frozen wire shape.
func MarshalCookies(cookies []Cookie) ([]byte, error) {
	wire := make([]WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = ToWire(c)
	}
	return json.Marshal(struct {
		Cookies []WireCookie `json:"cookies"`
	}{Cookies: wire})
}

// UnmarshalCookies decodes a bare JSON array of wire cookies (the rpc apply stdin
// payload) back into the cookie model.
func UnmarshalCookies(data []byte) ([]Cookie, error) {
	var wire []WireCookie
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	cookies := make([]Cookie, len(wire))
	for i, w := range wire {
		cookies[i] = FromWire(w)
	}
	return cookies, nil
}
