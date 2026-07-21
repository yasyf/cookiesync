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

// TestWireCookieJSONMatchesFrozenContract pins one cookie's exact v1 field names,
// order, and bytes.
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

// TestMarshalCookiesEnvelopeMatchesFrozenContract pins the exact v1 payload.
func TestMarshalCookiesEnvelopeMatchesFrozenContract(t *testing.T) {
	const want = `{"protocol_version":1,"cookies":[{"host_key":".x.com","name":"sid","value":"abc123","path":"/","expires_utc":13400000000000000,"last_update_utc":13350000000000000,"creation_utc":13300000000000000,"is_secure":true,"is_httponly":true,"samesite":2,"source_scheme":2,"source_port":443,"top_frame_site_key":"","has_cross_site_ancestor":0}]}`
	got, err := MarshalCookies([]Cookie{wireSample()})
	if err != nil {
		t.Fatalf("MarshalCookies: %v", err)
	}
	if string(got) != want {
		t.Fatalf("envelope JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestCookieWireRoundTrip proves a cookie survives the exact v1 envelope.
func TestCookieWireRoundTrip(t *testing.T) {
	in := []Cookie{wireSample(), digestCookie(".y.com", "tok", "/app", 42)}
	body, err := MarshalCookies(in)
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

func TestCookieWireRejectsMissingWrongAndExtendedProtocol(t *testing.T) {
	for _, body := range []string{
		`{"cookies":[]}`,
		`{"protocol_version":2,"cookies":[]}`,
		`{"protocol_version":1,"cookies":[],"legacy":true}`,
	} {
		if _, err := UnmarshalCookies([]byte(body)); err == nil {
			t.Fatalf("UnmarshalCookies(%s) succeeded", body)
		}
	}
}

func TestOriginWireRoundTripAndRejectsForeignEpochs(t *testing.T) {
	in := []OriginStorage{{
		Origin:         "https://app.example",
		LocalStorage:   []WebStorageEntry{{Name: "local", Value: "one"}},
		SessionStorage: []WebStorageEntry{{Name: "session", Value: "two"}},
	}}
	body, err := MarshalOrigins(in)
	if err != nil {
		t.Fatalf("MarshalOrigins: %v", err)
	}
	got, err := UnmarshalOrigins(body)
	if err != nil {
		t.Fatalf("UnmarshalOrigins: %v", err)
	}
	if len(got) != 1 || got[0].Origin != in[0].Origin || len(got[0].LocalStorage) != 1 || got[0].LocalStorage[0] != in[0].LocalStorage[0] {
		t.Fatalf("origin round trip = %+v, want %+v", got, in)
	}

	for _, foreign := range []string{
		`{"origins":[]}`,
		`{"protocol_version":2,"origins":[]}`,
		`{"protocol_version":1,"origins":[],"legacy":true}`,
		`{"protocol_version":1}`,
	} {
		if _, err := UnmarshalOrigins([]byte(foreign)); err == nil {
			t.Fatalf("UnmarshalOrigins(%s) succeeded", foreign)
		}
	}
}
