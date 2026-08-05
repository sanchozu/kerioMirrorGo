package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestHostRouterMiddleware(t *testing.T) {
	tests := []struct {
		name string
		host string
		url  string
		want string
	}{
		{"antivirus link", "bdupdate.kerio.com", "/update.php?product=KWF&version=9.5.0", "/api/kerio/updates/antivirus/link"},
		{"antivirus file", "bdupdate.kerio.com", "/v2/repository/a/file.gzip", "/api/kerio/updates/antivirus/files/v2/repository/a/file.gzip"},
		{"antispam file", "bda-update.kerio.com:80", "/versions.id", "/api/kerio/updates/antispam/files/versions.id"},
		{"geoip", "ids-update.kerio.com", "/geoip/update.php?version=5.0", "/api/kerio/updates/geoip/link"},
		{"distro", "prod-update.kerio.com", "/checknew.php", "/api/kerio/updates/distro/check"},
		{"registration", "register.kerio.com", "/registration/LD.php", "/api/kerio/updates/registration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest("GET", tt.url, nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			h := HostRouterMiddleware()(func(c echo.Context) error {
				if got := c.Request().URL.Path; got != tt.want {
					t.Fatalf("path = %q, want %q", got, tt.want)
				}
				return nil
			})
			if err := h(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}
