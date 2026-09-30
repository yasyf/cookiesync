package cookie

import "strings"

// Host parsing and the cookie send-rule: what a browser would send to a host.
//
// There is no public-suffix list here: Applies implements the actual
// domain-match the browser uses, which is all we need to pick the cookies for one
// target host.

// NormalizeHost returns the bare, lowercase host of a URL or domain, stripping the
// scheme, path, query, fragment, userinfo, port, and any leading dot; a bracketed
// IPv6 literal keeps its brackets.
func NormalizeHost(url string) Host {
	v := strings.ToLower(strings.TrimSpace(url))
	if scheme, rest, found := strings.Cut(v, "://"); found && !strings.ContainsAny(scheme, "/?#@") {
		v = rest
	}
	if i := strings.IndexAny(v, "/\\?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if strings.HasPrefix(v, "[") {
		if end := strings.Index(v, "]"); end >= 0 {
			return Host(v[:end+1])
		}
	}
	v, _, _ = strings.Cut(v, ":")
	return Host(strings.Trim(v, "."))
}

// URLScheme returns the lowercased scheme of a URL, or "https" for a bare domain.
func URLScheme(url string) string {
	if scheme, _, found := strings.Cut(url, "://"); found {
		return strings.ToLower(scheme)
	}
	return "https"
}

// Applies reports whether a browser would send a cookie with this hostKey to
// host. Domain cookies (leading dot) match the base host and any subdomain;
// host-only cookies match exactly. The comparison is case-insensitive.
func Applies(hostKey HostKey, host Host) bool {
	hk := strings.ToLower(string(hostKey))
	rh := strings.ToLower(string(host))
	if strings.HasPrefix(hk, ".") {
		return rh == hk[1:] || strings.HasSuffix(rh, hk)
	}
	return rh == hk
}
