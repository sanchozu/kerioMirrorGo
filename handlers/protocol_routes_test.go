package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kerio-mirror-go/config"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	got, err := safeJoin(root, filepath.Join("v2", "repository", "file.gzip"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "v2", "repository", "file.gzip")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := safeJoin(root, filepath.Join("..", "outside")); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestCompareVersion(t *testing.T) {
	if compareVersion("9.4.2-100", "9.5.0-9017") >= 0 {
		t.Fatal("older version was not detected")
	}
	if compareVersion("9.5.0-9017", "9.5.0-9017") != 0 {
		t.Fatal("equal versions differ")
	}
	if compareVersion("9.5.1-1", "9.5.0-9017") <= 0 {
		t.Fatal("newer version was not detected")
	}
}

func TestParseKerioUpdate(t *testing.T) {
	version, link, err := parseKerioUpdate("0:5.123\nfull:https://example.test/ids_5_123.gz")
	if err != nil {
		t.Fatal(err)
	}
	if version != 123 || link != "https://example.test/ids_5_123.gz" {
		t.Fatalf("unexpected result: %d %q", version, link)
	}
}

func registrationPost(t *testing.T, form url.Values) (*httptest.ResponseRecorder, echo.Context) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/kerio/updates/registration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	return rec, e.NewContext(req, rec)
}

func TestRegistrationEmulation_Lookup(t *testing.T) {
	t.Setenv("KERIO_REGISTRATION_EMULATION", "true")
	t.Setenv("KERIO_REGISTRATION_FORCE_UNLIMITED", "true")

	form := url.Values{}
	form.Set("command", "lookup")
	form.Set("base_id", "test-base-id")
	form.Set("token", "test-token")
	rec, c := registrationPost(t, form)

	cfg := &config.Config{LicenseNumber: "LIC"}
	logger := logrus.New()
	if err := registrationProxyHandler(cfg, logger)(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Kerio-Reply-Code") != "200" {
		t.Errorf("X-Kerio-Reply-Code = %q, want 200", rec.Header().Get("X-Kerio-Reply-Code"))
	}
	if rec.Header().Get("X-Kerio-Token") != "test-token" {
		t.Errorf("X-Kerio-Token = %q, want test-token", rec.Header().Get("X-Kerio-Token"))
	}
	body := rec.Body.String()
	for _, want := range []string{"base_id: test-base-id", "type: Server", "users: UNLIMITED", "total_users: UNLIMITED", "reg_type: TRIAL", "product: Kerio Control"} {
		if !strings.Contains(body, want) {
			t.Errorf("Lookup body missing %q", want)
		}
	}
	if !strings.Contains(body, "expires: 20") {
		t.Errorf("Lookup body missing future expiry date: %q", body)
	}
}

func TestRegistrationEmulation_Readinfo(t *testing.T) {
	t.Setenv("KERIO_REGISTRATION_EMULATION", "true")
	t.Setenv("KERIO_REGISTRATION_FORCE_UNLIMITED", "true")

	form := url.Values{}
	form.Set("command", "readinfo")
	form.Set("base_id", "base-1")
	form.Set("token", "tok")
	rec, c := registrationPost(t, form)

	cfg := &config.Config{}
	if err := registrationProxyHandler(cfg, logrus.New())(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Kerio-Reply-Message") != "OK, registration data follows" {
		t.Errorf("X-Kerio-Reply-Message = %q", rec.Header().Get("X-Kerio-Reply-Message"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "addon_list[]: base-1;Server;Kerio Control server") {
		t.Errorf("Readinfo missing addon_list: %q", body)
	}
	if !strings.Contains(body, "users: UNLIMITED") {
		t.Errorf("Readinfo missing users: %q", body)
	}
}

func TestRegistrationEmulation_Stored(t *testing.T) {
	t.Setenv("KERIO_REGISTRATION_EMULATION", "true")

	form := url.Values{}
	form.Set("command", "stored")
	form.Set("base_id", "stored-id")
	form.Set("token", "tok")
	rec, c := registrationPost(t, form)

	cfg := &config.Config{}
	if err := registrationProxyHandler(cfg, logrus.New())(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Kerio-Reply-Message") != "OK, verified" {
		t.Errorf("X-Kerio-Reply-Message = %q", rec.Header().Get("X-Kerio-Reply-Message"))
	}
	if strings.TrimSpace(rec.Body.String()) != "base_id: stored-id" {
		t.Errorf("Stored body = %q", rec.Body.String())
	}
}

func TestRegistrationEmulation_ConnectFromCache(t *testing.T) {
	t.Setenv("KERIO_REGISTRATION_EMULATION", "true")

	dir := t.TempDir()
	t.Chdir(dir)

	content := strings.Repeat("pad", 300) +
		"security_image image_signature show_image"
	if err := os.MkdirAll(filepath.Join("mirror", "registration"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("mirror", "registration", "security_image"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("command", "connect")
	rec, c := registrationPost(t, form)

	cfg := &config.Config{}
	if err := registrationProxyHandler(cfg, logrus.New())(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Kerio-Reply-Code") != "200" {
		t.Errorf("X-Kerio-Reply-Code = %q, want 200", rec.Header().Get("X-Kerio-Reply-Code"))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-kerio-signed-png" {
		t.Errorf("Content-Type = %q, want application/x-kerio-signed-png", ct)
	}
	if !strings.Contains(rec.Body.String(), "security_image") {
		t.Errorf("Captcha body missing content")
	}
}

func TestCachedVendorFileWithoutDiscoveredCDNForbidden(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/kerio/updates/antivirus/files/av64bit_97276/versions.dat", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("*")
	c.SetParamValues("av64bit_97276/versions.dat")

	cfg := &config.Config{BitdefenderMode: "proxy"}
	if err := cachedVendorFileHandler(cfg, logrus.New(), "antivirus")(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}
}

func TestCachedVendorFileVersionsDatGzipUsesClientFallback(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/kerio/updates/antivirus/files/v2/repository/abc/versions.dat.gz", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("*")
	c.SetParamValues("v2/repository/abc/versions.dat.gz")

	cfg := &config.Config{BitdefenderMode: "proxy"}
	cfg.SetKerioCDN("https://bdupdate-cdn.kerio.com/repository")
	if err := cachedVendorFileHandler(cfg, logrus.New(), "antivirus")(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("Expected status 404 for compressed metadata fallback, got %d", rec.Code)
	}
}
