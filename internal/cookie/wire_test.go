package cookie

import (
	"encoding/json"
	"testing"
)

// wireSample is the cookie the wire-contract oracle was computed from.
func wireSample() Cookie {
	return Cookie{
		HostKey:              ".x.com",
		Name:                 "sid",
		Value:                "abc123",
		Path:                 "/",
		ExpiresUTC:           13_400_000_000_000_000,
		LastUpdateUTC:        13_350_000_000_000_000,
		CreationUTC:          13_300_000_000_000_000,
		IsSecure:             true,
		IsHTTPOnly:           true,
		SameSite:             2,
		SourceScheme:         2,
		SourcePort:           443,
		TopFrameSiteKey:      "",
		HasCrossSiteAncestor: 0,
	}
}

// TestWireCookieJSONMatchesFrozenContract pins one cookie's wire JSON to the exact
// bytes the Python dataclasses.asdict(Cookie) emits — the frozen field names and order
// the ssh peer protocol and agent-browser skill depend on.
func TestWireCookieJSONMatchesFrozenContract(t *testing.T) {
	const want = `{"host_key":".x.com","name":"sid","value":"abc123","path":"/","expires_utc":13400000000000000,"last_update_utc":13350000000000000,"creation_utc":13300000000000000,"is_secure":true,"is_httponly":true,"samesite":2,"source_scheme":2,"source_port":443,"top_frame_site_key":"","has_cross_site_ancestor":0}`
	got, err := json.Marshal(ToWire(wireSample()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != want {
		t.Fatalf("wire JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestMarshalCookiesEnvelopeMatchesFrozenContract pins the {"cookies": [...]} payload
// the rpc extract contract emits to the exact Python bytes.
func TestMarshalCookiesEnvelopeMatchesFrozenContract(t *testing.T) {
	const want = `{"cookies":[{"host_key":".x.com","name":"sid","value":"abc123","path":"/","expires_utc":13400000000000000,"last_update_utc":13350000000000000,"creation_utc":13300000000000000,"is_secure":true,"is_httponly":true,"samesite":2,"source_scheme":2,"source_port":443,"top_frame_site_key":"","has_cross_site_ancestor":0}]}`
	got, err := MarshalCookies([]Cookie{wireSample()})
	if err != nil {
		t.Fatalf("MarshalCookies: %v", err)
	}
	if string(got) != want {
		t.Fatalf("envelope JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestCookieWireRoundTrip proves a cookie survives a wire encode/decode unchanged, so
// the rpc apply stdin (a bare array of wire cookies) reconstructs the model exactly.
func TestCookieWireRoundTrip(t *testing.T) {
	in := []Cookie{wireSample(), digestCookie(".y.com", "tok", "/app", 42)}
	body, err := json.Marshal(toWireSlice(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalCookies(body)
	if err != nil {
		t.Fatalf("UnmarshalCookies: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("round-trip length = %d, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("round-trip cookie %d = %+v, want %+v", i, got[i], in[i])
		}
	}
}

func toWireSlice(cookies []Cookie) []WireCookie {
	out := make([]WireCookie, len(cookies))
	for i, c := range cookies {
		out[i] = ToWire(c)
	}
	return out
}
