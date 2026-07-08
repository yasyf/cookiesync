package cookie

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Render a StorageState to one of the cookie wire formats.
//
// The Playwright/agent-browser format is the load-bearing one: "agent-browser
// --state -" consumes the standard {"cookies": [...], "origins": [...]} storageState
// shape, whose origins carry each origin's localStorage. The webstorage format is the
// sidecar carrying both localStorage and sessionStorage (Playwright storageState has no
// sessionStorage slot). The other formats serve cookies.txt (netscape), a "Cookie:"
// request header, and a raw JSON array of the same per-cookie objects.
//
// The JSON output is byte-compatible with Python's json.dumps: ", "/": " separators
// and ensure_ascii=True escaping, so a rendered state is identical across the two
// implementations.

// OutputFormat is the wire format Render emits a StorageState in.
type OutputFormat string

const (
	// FormatPlaywright is the Playwright storageState object: {"cookies": [...], "origins": [...]}.
	FormatPlaywright OutputFormat = "playwright"
	// FormatNetscape is the cookies.txt tab-separated format.
	FormatNetscape OutputFormat = "netscape"
	// FormatHeader is a request "Cookie:" header value: name=value pairs joined by "; ".
	FormatHeader OutputFormat = "header"
	// FormatJSON is a bare JSON array of the per-cookie Playwright objects.
	FormatJSON OutputFormat = "json"
	// FormatWebStorage is the web-storage sidecar: {"origins": [{origin, localStorage,
	// sessionStorage}]}, the only channel carrying sessionStorage.
	FormatWebStorage OutputFormat = "webstorage"
)

// samesiteGetcookie maps a get-cookie sameSite string (lowercased) to Chrome's int.
var samesiteGetcookie = map[string]int{"strict": 2, "lax": 1, "none": 0}

// Render returns the lines of state rendered in fmt, ready to stream to stdout. An
// unknown format yields no lines.
func Render(state StorageState, format OutputFormat) []string {
	switch format {
	case FormatPlaywright:
		return []string{`{"cookies": ` + playwrightArray(state.Cookies) + `, "origins": ` + playwrightOrigins(state.Origins) + `}`}
	case FormatWebStorage:
		return []string{`{"origins": ` + webStorageOrigins(state.Origins) + `}`}
	case FormatJSON:
		return []string{playwrightArray(state.Cookies)}
	case FormatNetscape:
		lines := make([]string, 0, len(state.Cookies)+1)
		lines = append(lines, "# Netscape HTTP Cookie File")
		for _, c := range state.Cookies {
			lines = append(lines, netscapeLine(c))
		}
		return lines
	case FormatHeader:
		pairs := make([]string, len(state.Cookies))
		for i, c := range state.Cookies {
			pairs[i] = c.Name + "=" + c.Value
		}
		return []string{strings.Join(pairs, "; ")}
	default:
		return nil
	}
}

func playwrightArray(cookies []Cookie) string {
	objs := make([]string, len(cookies))
	for i, c := range cookies {
		objs[i] = playwrightCookie(c)
	}
	return "[" + strings.Join(objs, ", ") + "]"
}

// playwrightCookie renders one Playwright-shaped cookie object. sameSite=None forces
// secure true, since browsers reject the pair otherwise.
func playwrightCookie(c Cookie) string {
	same := samesiteToPlaywright(c.SameSite)
	members := []string{
		`"name": ` + pyJSONString(c.Name),
		`"value": ` + pyJSONString(c.Value),
		`"domain": ` + pyJSONString(string(c.HostKey)),
		`"path": ` + pyJSONString(c.Path),
		`"expires": ` + expiresJSON(c.ExpiresUTC),
		`"httpOnly": ` + strconv.FormatBool(c.IsHTTPOnly),
		`"secure": ` + strconv.FormatBool(c.IsSecure || same == "None"),
		`"sameSite": ` + pyJSONString(same),
	}
	return "{" + strings.Join(members, ", ") + "}"
}

// playwrightOrigins renders the storageState "origins" array: one object per origin
// carrying its localStorage. Origins with no localStorage are dropped, and an empty
// result renders "[]" byte-identically to the cookie-only path. Playwright's
// storageState has no sessionStorage slot, so only localStorage is emitted here.
func playwrightOrigins(origins []OriginStorage) string {
	objs := make([]string, 0, len(origins))
	for _, o := range origins {
		if len(o.LocalStorage) == 0 {
			continue
		}
		objs = append(objs, "{"+strings.Join([]string{
			`"origin": ` + pyJSONString(o.Origin),
			`"localStorage": ` + webStorageArray(o.LocalStorage),
		}, ", ")+"}")
	}
	return "[" + strings.Join(objs, ", ") + "]"
}

// webStorageOrigins renders the webstorage sidecar's "origins" array: one object per
// origin carrying both its localStorage and its sessionStorage.
func webStorageOrigins(origins []OriginStorage) string {
	objs := make([]string, len(origins))
	for i, o := range origins {
		objs[i] = "{" + strings.Join([]string{
			`"origin": ` + pyJSONString(o.Origin),
			`"localStorage": ` + webStorageArray(o.LocalStorage),
			`"sessionStorage": ` + webStorageArray(o.SessionStorage),
		}, ", ") + "}"
	}
	return "[" + strings.Join(objs, ", ") + "]"
}

// webStorageArray renders a run of web-storage entries as a JSON array of {name, value}
// objects, each string escaped the Python-json.dumps way.
func webStorageArray(entries []WebStorageEntry) string {
	objs := make([]string, len(entries))
	for i, e := range entries {
		objs[i] = "{" + strings.Join([]string{
			`"name": ` + pyJSONString(e.Name),
			`"value": ` + pyJSONString(e.Value),
		}, ", ") + "}"
	}
	return "[" + strings.Join(objs, ", ") + "]"
}

// expiresJSON renders the expires field: the integer -1 for a session cookie,
// otherwise the Unix-seconds float in Python's repr form.
func expiresJSON(expires ChromeMicros) string {
	if seconds, session := chromeMicrosToUnix(expires); !session {
		return pyFloatRepr(seconds)
	}
	return "-1"
}

// netscapeLine renders one cookies.txt row: tab-separated, with the leading-dot
// subdomain flag. A session cookie's expiry field is 0.
func netscapeLine(c Cookie) string {
	expiry := "0"
	if seconds, session := chromeMicrosToUnix(c.ExpiresUTC); !session {
		expiry = strconv.FormatInt(int64(seconds), 10)
	}
	return strings.Join([]string{
		string(c.HostKey),
		flag(strings.HasPrefix(string(c.HostKey), ".")),
		c.Path,
		flag(c.IsSecure),
		expiry,
		c.Name,
		c.Value,
	}, "\t")
}

func flag(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}

// pyFloatRepr renders f the way CPython's repr()/json.dumps does: shortest
// round-tripping digits, a decimal point always present in fixed notation, and
// exponential notation only when the decimal exponent is < -4 or >= 16.
func pyFloatRepr(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case math.IsNaN(f):
		return "NaN"
	}
	mant, expStr, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	exp, _ := strconv.Atoi(expStr)
	neg := strings.HasPrefix(mant, "-")
	intPart, fracPart, _ := strings.Cut(strings.TrimPrefix(mant, "-"), ".")
	digits := intPart + fracPart

	var body string
	switch {
	case exp < -4 || exp >= 16:
		m := digits
		if len(digits) > 1 {
			m = digits[:1] + "." + digits[1:]
		}
		sign, e := "+", exp
		if e < 0 {
			sign, e = "-", -e
		}
		body = fmt.Sprintf("%se%s%02d", m, sign, e)
	case exp >= 0:
		if lead := exp + 1; lead >= len(digits) {
			body = digits + strings.Repeat("0", lead-len(digits)) + ".0"
		} else {
			body = digits[:lead] + "." + digits[lead:]
		}
	default:
		body = "0." + strings.Repeat("0", -exp-1) + digits
	}
	if neg {
		return "-" + body
	}
	return body
}

// pyJSONString renders s as a JSON string the way Python's json.dumps does with
// ensure_ascii=True: short escapes for the standard controls, \uXXXX for every other
// control and all non-ASCII (surrogate pairs above U+FFFF), and "/" left unescaped.
func pyJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			switch {
			case r < 0x20 || r >= 0x7f:
				if r > 0xffff {
					hi, lo := utf16.EncodeRune(r)
					fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
				} else {
					fmt.Fprintf(&b, `\u%04x`, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// NormalizeGetcookieRecord maps one @mherod/get-cookie JSON record into the Cookie
// model. get-cookie reliably emits name/value/domain; the rest varies, so path
// defaults to "/", secure follows the URL scheme, and attributes come from a meta
// block when present. A session cookie (no expiry) lands at ChromeMicros(0).
func NormalizeGetcookieRecord(record map[string]any, url string) Cookie {
	host := NormalizeHost(url)
	hostKey := HostKey(host)
	if domain := asGetcookieString(record["domain"]); domain != "" {
		hostKey = HostKey(domain)
	}
	path := asGetcookieString(record["path"])
	if path == "" {
		path = "/"
	}
	meta, _ := record["meta"].(map[string]any)
	return Cookie{
		HostKey:       hostKey,
		Name:          asGetcookieString(record["name"]),
		Value:         asGetcookieString(record["value"]),
		Path:          path,
		ExpiresUTC:    recordExpiry(record),
		LastUpdateUTC: 0,
		CreationUTC:   0,
		IsSecure:      metaSecure(meta, url),
		IsHTTPOnly:    metaHTTPOnly(meta),
		SameSite:      metaSameSite(meta),
		SourceScheme:  2,
		SourcePort:    443,
	}
}

func metaSecure(meta map[string]any, url string) bool {
	if v, ok := meta["secure"]; ok {
		return truthy(v)
	}
	return URLScheme(url) == "https"
}

func metaHTTPOnly(meta map[string]any) bool {
	if v, ok := meta["httpOnly"]; ok {
		return truthy(v)
	}
	return truthy(meta["httponly"])
}

func metaSameSite(meta map[string]any) int {
	raw := meta["sameSite"]
	if raw == nil {
		raw = meta["samesite"]
	}
	name := strings.ToLower(asGetcookieString(raw))
	if name == "" {
		name = "lax"
	}
	if v, ok := samesiteGetcookie[name]; ok {
		return v
	}
	return 1
}

func recordExpiry(record map[string]any) ChromeMicros {
	raw, ok := record["expiry"]
	if !ok {
		raw = record["expires"]
	}
	switch v := raw.(type) {
	case bool:
		return 0
	case float64:
		return unixSecondsToChromeMicros(v)
	case int:
		return unixSecondsToChromeMicros(float64(v))
	case int64:
		return unixSecondsToChromeMicros(float64(v))
	case string:
		if s := strings.TrimSpace(v); isDigits(strings.TrimPrefix(s, "-")) && s != "" && s != "-" {
			f, err := strconv.ParseFloat(s, 64)
			if err == nil {
				return unixSecondsToChromeMicros(f)
			}
		}
		return 0
	default:
		return 0
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// truthy mirrors Python's bool(x) for the JSON scalar types a get-cookie meta value
// can hold.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	default:
		return true
	}
}

// asGetcookieString reads a JSON string field, treating a missing or non-string
// value as empty.
func asGetcookieString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
