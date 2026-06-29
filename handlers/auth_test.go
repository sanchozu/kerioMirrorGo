package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestValidAdminToken(t *testing.T) {
	if !validAdminToken("secret", "secret") {
		t.Fatal("expected matching token to validate")
	}
	if validAdminToken("secret", "wrong") {
		t.Fatal("expected mismatched token to fail")
	}
	if !validAdminToken("", "admin") {
		t.Fatal("expected empty configured token to use default admin token")
	}
	if validAdminToken("secret", "") {
		t.Fatal("expected empty provided token to fail")
	}
}

func TestAdminSessionValidation(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminSessionValue("secret")})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if !hasValidAdminSession(c, "secret") {
		t.Fatal("expected valid session cookie")
	}
	if hasValidAdminSession(c, "other") {
		t.Fatal("expected session cookie to be invalid after token change")
	}
}

func TestIsCrawlerUserAgent(t *testing.T) {
	tests := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 Firefox/153.0", false},
		{"Googlebot/2.1", true},
		{"curl/8.0.1", true},
		{"TelegramBot (like TwitterBot)", true},
	}

	for _, tt := range tests {
		if got := isCrawlerUserAgent(tt.ua); got != tt.want {
			t.Fatalf("isCrawlerUserAgent(%q) = %v, want %v", tt.ua, got, tt.want)
		}
	}
}

func TestNormalizeLanguage(t *testing.T) {
	tests := map[string]string{
		"":     "",
		"uk":   "uk",
		"ua":   "uk",
		"en":   "en",
		" EN ": "en",
		"de":   "",
	}
	for input, want := range tests {
		if got := normalizeLanguage(input); got != want {
			t.Fatalf("normalizeLanguage(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsHTTPSRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if isHTTPSRequest(req) {
		t.Fatal("plain request should not be secure")
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	if !isHTTPSRequest(req) {
		t.Fatal("X-Forwarded-Proto=https should be secure")
	}
}
