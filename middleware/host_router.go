package middleware

import (
	"net"
	"path"
	"strings"

	"github.com/labstack/echo/v4"
)

// HostRouterMiddleware rewrites requests made to the original Kerio update
// hostnames to internal canonical API routes. It is intended for Echo.Pre so
// the rewritten path is used by the router.
func HostRouterMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			host := normalizedHost(r.Host)
			p := r.URL.Path
			if strings.HasPrefix(p, "/api/kerio/updates/") {
				return next(c)
			}

			switch host {
			case "bda-update.kerio.com":
				r.URL.Path = "/api/kerio/updates/antispam/files" + p
			case "bdupdate.kerio.com":
				if path.Clean(p) == "/update.php" && r.URL.Query().Get("product") != "" {
					r.URL.Path = "/api/kerio/updates/antivirus/link"
				} else {
					r.URL.Path = "/api/kerio/updates/antivirus/files" + p
				}
			case "ids-update.kerio.com":
				if strings.HasPrefix(p, "/geoip/") {
					r.URL.Path = "/api/kerio/updates/geoip/link"
				} else {
					r.URL.Path = "/api/kerio/updates/ids/link"
				}
			case "download.kerio.com":
				r.URL.Path = "/api/kerio/updates/ids/files/" + path.Base(p)
			case "shieldmatrix-updates.gfikeriocontrol.com":
				r.URL.Path = "/api/kerio/updates/shieldmatrix/link"
			case "wf-activation.kerio.com":
				r.URL.Path = "/api/kerio/updates/webfilter/key"
			case "prod-update.kerio.com":
				r.URL.Path = "/api/kerio/updates/distro/check"
			case "register.kerio.com":
				r.URL.Path = "/api/kerio/updates/registration"
			default:
				if strings.Contains(host, "cloudfront.net") {
					parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
					if len(parts) == 2 {
						r.URL.Path = "/api/kerio/updates/shieldmatrix/files/" + parts[1]
					}
				}
			}
			return next(c)
		}
	}
}

func normalizedHost(hostport string) string {
	hostport = strings.TrimSpace(strings.ToLower(hostport))
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(hostport, "[]")
}
