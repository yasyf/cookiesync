//go:build darwin

package auth

import "github.com/yasyf/cookiesync/internal/cookie"

func routable(cookie.Browser) error {
	return nil
}
