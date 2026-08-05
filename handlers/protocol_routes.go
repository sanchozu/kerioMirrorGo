package handlers

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"kerio-mirror-go/config"
	"kerio-mirror-go/db"
	"kerio-mirror-go/mirror"
	"kerio-mirror-go/telegram"
	"kerio-mirror-go/utils"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

const apiBase = "/api/kerio/updates"

var cacheLocks sync.Map

func RegisterProtocolRoutes(e *echo.Echo, cfg *config.Config, logger *logrus.Logger) {
	e.GET(apiBase+"/ids/link", idsLinkHandler(cfg, logger))
	e.GET(apiBase+"/ids/files/:name", idsFileHandler())
	e.GET(apiBase+"/geoip/link", geoIPLinkHandler(cfg, logger))
	e.GET(apiBase+"/geoip/files/:name", idsFileHandler())

	e.GET(apiBase+"/antivirus/link", antivirusLinkHandler(cfg, logger))
	e.GET(apiBase+"/antivirus/files/*", cachedVendorFileHandler(cfg, logger, "antivirus"))
	e.GET(apiBase+"/antispam/files/*", cachedVendorFileHandler(cfg, logger, "antispam"))

	e.GET(apiBase+"/shieldmatrix/link", shieldMatrixCheckUpdateHandler(cfg, logger))
	e.GET(apiBase+"/shieldmatrix/files/version", shieldMatrixVersionHandler(cfg))
	e.GET(apiBase+"/shieldmatrix/files/*", shieldMatrixCanonicalFileHandler(cfg, logger))
	e.GET(apiBase+"/webfilter/key", webFilterKeyHandler(cfg))

	e.POST(apiBase+"/distro/check", distroCheckHandler(logger))
	e.GET(apiBase+"/distro/files/:name", distroFileHandler())
	e.HEAD(apiBase+"/registration", registrationProxyHandler(cfg, logger))
	e.POST(apiBase+"/registration", registrationProxyHandler(cfg, logger))

	// Legacy host/path aliases used by Kerio products.
	e.POST("/checknew.php", distroCheckHandler(logger))
	e.HEAD("/registration/LD.php", registrationProxyHandler(cfg, logger))
	e.POST("/registration/LD.php", registrationProxyHandler(cfg, logger))
}

func idsLinkHandler(cfg *config.Config, logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		major, err := parseMajor(c.QueryParam("version"))
		if err != nil || major < 1 || major > 5 {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		conn, err := sql.Open("sqlite", cfg.DatabasePath)
		if err != nil {
			return c.String(http.StatusInternalServerError, "500 Internal Server Error")
		}
		defer conn.Close()
		version := db.GetIDSVersion(conn, strconv.Itoa(major))
		var filename string
		if version == 0 || conn.QueryRow(`SELECT filename FROM ids_versions WHERE version_id = ?`, "ids"+strconv.Itoa(major)).Scan(&filename) != nil {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		return c.String(http.StatusOK, fmt.Sprintf("0:%d.%d\nfull:%s%s/ids/files/%s", major, version, publicBaseURL(c), apiBase, filename))
	}
}

func idsFileHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		name := c.Param("name")
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(name) {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		file, err := safeJoin("mirror", name)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		if info, err := os.Stat(file); err != nil || !info.Mode().IsRegular() {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		return c.File(file)
	}
}

func geoIPLinkHandler(cfg *config.Config, logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		major, err := parseMajor(c.QueryParam("version"))
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		if major == 4 {
			return idsLinkHandler(cfg, logger)(c)
		}
		if major != 5 || cfg.GetLicenseNumber() == "" {
			return c.String(http.StatusNotFound, "404 Not found")
		}

		upstream, err := url.Parse("https://ids-update.kerio.com/geoip/update.php")
		if err != nil {
			return c.String(http.StatusInternalServerError, "500 Internal Server Error")
		}
		q := upstream.Query()
		q.Set("id", cfg.GetLicenseNumber())
		q.Set("version", c.QueryParam("version"))
		q.Set("tag", c.QueryParam("tag"))
		upstream.RawQuery = q.Encode()
		body, status, err := upstreamBytes(cfg, http.MethodGet, upstream.String(), nil, map[string]string{"Host": "ids-update.kerio.com"})
		if err != nil || status != http.StatusOK {
			return c.String(http.StatusBadGateway, "502 Bad Gateway")
		}
		version, downloadURL, err := parseKerioUpdate(string(body))
		if err != nil || downloadURL == "" {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		name := path.Base(downloadURL)
		local, err := safeJoin("mirror", name)
		if err != nil {
			return c.String(http.StatusBadGateway, "502 Bad Gateway")
		}
		if err := downloadAtomic(cfg, downloadURL, local, nil); err != nil {
			logger.Errorf("GeoIP v5 download failed: %v", err)
			return c.String(http.StatusBadGateway, "502 Bad Gateway")
		}
		return c.String(http.StatusOK, fmt.Sprintf("0:5.%d\nfull:%s%s/geoip/files/%s", version, publicBaseURL(c), apiBase, name))
	}
}

func antivirusLinkHandler(cfg *config.Config, logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		if cfg.BitdefenderMode == "disabled" {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		base := strings.TrimSpace(os.Getenv("KERIO_ANTIVIRUS_UPSTREAM"))
		if base == "" {
			base = cfg.BitdefenderProxyBaseURL
		}
		if base == "" {
			base = "https://upgrade.bitdefender.com"
		}
		if strings.Contains(base, "bdupdate.kerio.com") {
			cdn, err := discoverKerioCDN(cfg, c.QueryParam("version"))
			if err != nil {
				if errors.Is(err, errCDNLicenseInvalid) {
					license := cfg.GetLicenseNumber()
					cfg.ClearLicenseNumber()
					notifyCDNError(cfg, logger, "license %s invalid or expired, Kerio CDN updates disabled: %v", license, err)
				} else {
					notifyCDNError(cfg, logger, "CDN discovery failed for version %q: %v", c.QueryParam("version"), err)
				}
				return c.String(http.StatusBadGateway, "502 Bad Gateway")
			}
			base = cdn
		}
		if err := writeAtomicText(filepath.Join("mirror", "antivirus", "upstream.url"), strings.TrimRight(base, "/")); err != nil {
			return c.String(http.StatusInternalServerError, "500 Internal Server Error")
		}
		if envBool("KERIO_ANTIVIRUS_DIRECT", false) {
			return c.String(http.StatusOK, "THDdir="+strings.TrimRight(base, "/"))
		}
		return c.String(http.StatusOK, "THDdir="+publicBaseURL(c)+apiBase+"/antivirus/files")
	}
}

func cachedVendorFileHandler(cfg *config.Config, logger *logrus.Logger, service string) echo.HandlerFunc {
	return func(c echo.Context) error {
		if cfg.BitdefenderMode == "disabled" {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		rel := strings.TrimPrefix(c.Param("*"), "/")
		if rel == "" {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		// Сжатый versions.dat.gz намеренно не отдаём (404): клиент Kerio
		// откатится на распакованный versions.dat, который зеркало патчит
		// под Linux-движок. Подпись versions.sig при этом остаётся валидной.
		if path.Base(rel) == "versions.dat.gz" {
			logger.Debugf("%s: skipping compressed versions.dat.gz for %q (forcing uncompressed fallback)", service, rel)
			return c.String(http.StatusNotFound, "404 Not found")
		}
		upstream := vendorUpstream(cfg, service)
		if service == "antivirus" {
			if b, err := os.ReadFile(filepath.Join("mirror", "antivirus", "upstream.url")); err == nil && strings.TrimSpace(string(b)) != "" {
				upstream = strings.TrimSpace(string(b))
			}
			if mapped := mirror.LinuxEnginePath(rel); mapped != "" {
				rel = mapped
			}
		}
		local, err := safeJoin(filepath.Join("mirror", service), filepath.FromSlash(rel))
		if err != nil {
			return c.String(http.StatusForbidden, "403 Forbidden")
		}

		unlock := lockCache(local)
		defer unlock()
		if path.Base(rel) == "versions.id" && cacheExpired(local, metadataTTL()) {
			_ = removeVersionSiblings(filepath.Dir(local))
		}
		if info, err := os.Stat(local); err != nil || !info.Mode().IsRegular() {
			headers := map[string]string{"Accept": "*/*", "Connection": "Keep-Alive"}
			if service == "antivirus" {
				headers["User-Agent"] = "WSLib 1.4 [3, 0, 0, 94]"
			} else {
				headers["User-Agent"] = "WSLib 1.4 [3, 0, 0, 317]"
			}
			remote := strings.TrimRight(upstream, "/") + "/" + strings.TrimLeft(filepath.ToSlash(rel), "/")
			if err := downloadAtomic(cfg, remote, local, headers); err != nil {
				logger.Warnf("%s cache fetch failed for %s: %v", service, rel, err)
				return c.String(http.StatusBadGateway, "502 Bad Gateway")
			}
		}
		return serveVendorFile(c, local, rel, service == "antivirus")
	}
}

func serveVendorFile(c echo.Context, local, rel string, patchManifest bool) error {
	if !patchManifest {
		return c.File(local)
	}
	switch path.Base(rel) {
	case "versions.dat":
		b, err := os.ReadFile(local)
		if err != nil {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		return c.Blob(http.StatusOK, "application/octet-stream", mirror.PatchBitdefenderVersions(b))
	case "versions.dat.gz":
		b, err := os.ReadFile(local)
		if err != nil {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return c.File(local)
		}
		raw, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			return c.File(local)
		}
		var out bytes.Buffer
		zw := gzip.NewWriter(&out)
		_, _ = zw.Write(mirror.PatchBitdefenderVersions(raw))
		_ = zw.Close()
		return c.Blob(http.StatusOK, "application/gzip", out.Bytes())
	default:
		return c.File(local)
	}
}

func shieldMatrixVersionHandler(cfg *config.Config) echo.HandlerFunc {
	return func(c echo.Context) error {
		conn, err := sql.Open("sqlite", cfg.DatabasePath)
		if err != nil {
			return c.String(http.StatusInternalServerError, "500 Internal Server Error")
		}
		defer conn.Close()
		version := db.GetShieldMatrixVersion(conn)
		if version == "" {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		return c.String(http.StatusOK, version)
	}
}

func shieldMatrixCanonicalFileHandler(cfg *config.Config, logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		rel := strings.TrimPrefix(c.Param("*"), "/")
		if !strings.HasPrefix(rel, "ipv4/") && !strings.HasPrefix(rel, "ipv6/") {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		// Если upstream-версия изменилась, старые файлы (предыдущей версии)
		// очищаются, чтобы не отдавать устаревшие данные из кэша.
		if conn, dbErr := sql.Open("sqlite", cfg.DatabasePath); dbErr == nil {
			mirror.CheckAndPurgeShieldMatrixCache(conn, cfg, logger)
			_ = conn.Close()
		}
		local, err := safeJoin(filepath.Join("mirror", "matrix"), filepath.FromSlash(rel))
		if err != nil {
			return c.String(http.StatusForbidden, "403 Forbidden")
		}
		if _, err := os.Stat(local); err != nil {
			conn, dbErr := sql.Open("sqlite", cfg.DatabasePath)
			if dbErr != nil {
				return c.String(http.StatusInternalServerError, "500 Internal Server Error")
			}
			base := db.GetShieldMatrixCloudFrontURL(conn)
			_ = conn.Close()
			if base == "" || mirror.DownloadShieldMatrixFile(rel, base, cfg, logger) != nil {
				return c.String(http.StatusBadGateway, "502 Bad Gateway")
			}
		}
		return c.File(local)
	}
}

func distroCheckHandler(logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		const noUpdate = "--INFO--\nReminderId='1'\nReminderAuth='1'\nVersion='0'"
		if !envBool("KERIO_DISTRO_ENABLED", false) || c.FormValue("prod_code") != "KWF" {
			return c.String(http.StatusOK, noUpdate)
		}
		file := strings.TrimSpace(os.Getenv("KERIO_DISTRO_FILE"))
		target := strings.TrimSpace(os.Getenv("KERIO_DISTRO_VERSION"))
		if file == "" || target == "" || !regexp.MustCompile(`^[A-Za-z0-9_.-]+\.img$`).MatchString(file) {
			return c.String(http.StatusOK, noUpdate)
		}
		local, err := safeJoin(filepath.Join("mirror", "distros"), file)
		if err != nil {
			return c.String(http.StatusOK, noUpdate)
		}
		if _, err := os.Stat(local); err != nil {
			return c.String(http.StatusOK, noUpdate)
		}
		current := fmt.Sprintf("%s.%s.%s-%s", c.FormValue("prod_major"), c.FormValue("prod_minor"), c.FormValue("prod_build"), c.FormValue("prod_build_number"))
		if compareVersion(current, target) >= 0 {
			return c.String(http.StatusOK, noUpdate)
		}
		parts := versionNumbers(target)
		if len(parts) < 4 {
			return c.String(http.StatusOK, noUpdate)
		}
		packageCode := fmt.Sprintf("KWF:%03d.%03d.%05d.T.000.000", parts[0], parts[1], parts[2])
		response := fmt.Sprintf("--INFO--\nReminderId='1'\nReminderAuth='1'\nVersion='1'\nLicenseUsageReceived='1'\n--VERSION_BEGIN--\nPackageCode='%s'\nDescription='Kerio Control %s'\nComment='Kerio Control %s'\nDownloadURL='%s%s/distro/files/%s'\nDownloadURLtext='Download from local mirror'\nInfoURL='https://support.keriocontrol.gfi.com'\nInfoURLtext='View more information'\n--VERSION_END--", packageCode, target, target, publicBaseURL(c), apiBase, file)
		logger.Infof("Distro update offered: %s -> %s", current, target)
		return c.String(http.StatusOK, response)
	}
}

func distroFileHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		name := c.Param("name")
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+\.(img|sig)$`).MatchString(name) {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		file, err := safeJoin(filepath.Join("mirror", "distros"), name)
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		if info, err := os.Stat(file); err != nil || !info.Mode().IsRegular() {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		return c.File(file)
	}
}

func registrationProxyHandler(cfg *config.Config, logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		if envBool("KERIO_REGISTRATION_EMULATION", true) {
			return emulateRegistrationHandler(c, cfg, logger)
		}
		if !envBool("KERIO_REGISTRATION_PROXY", true) {
			return c.String(http.StatusNotFound, "404 Not found")
		}
		body, err := io.ReadAll(io.LimitReader(c.Request().Body, 2<<20))
		if err != nil {
			return c.String(http.StatusBadRequest, "400 Bad Request")
		}
		headers := map[string]string{"Content-Type": c.Request().Header.Get("Content-Type"), "User-Agent": c.Request().UserAgent()}
		respBody, status, respHeaders, err := upstreamResponse(cfg, c.Request().Method, "https://register.kerio.com/registration/LD.php", body, headers)
		if err != nil {
			logger.Warnf("Registration upstream failed: %v", err)
			return c.String(http.StatusBadGateway, "502 Bad Gateway")
		}
		copyResponseHeaders(c.Response().Header(), respHeaders)
		return c.Blob(status, respHeaders.Get("Content-Type"), respBody)
	}
}

// emulateRegistrationHandler обрабатывает команды протокола регистрации Kerio
// полностью локально (без обращения к register.kerio.com). Включено через
// KERIO_REGISTRATION_EMULATION=true (по умолчанию true).
func emulateRegistrationHandler(c echo.Context, cfg *config.Config, logger *logrus.Logger) error {
	if c.Request().Method == http.MethodHead {
		c.Response().Header().Set("X-Kerio-Token", "")
		c.Response().Header().Set("X-Kerio-Reply-Code", "500")
		c.Response().Header().Set("X-Kerio-Reply-Message", "Internal Server Error")
		return c.String(http.StatusOK, "")
	}
	command := strings.ToLower(strings.TrimSpace(c.FormValue("command")))
	baseID := c.FormValue("base_id")
	token := c.FormValue("token")
	logger.Debugf("Registration emulation: command=%q base_id=%q", command, baseID)
	switch command {
	case "connect":
		return emulateRegistrationConnect(c, cfg, logger)
	case "lookup":
		return emulateRegistrationLookup(c, logger, baseID, token)
	case "readinfo":
		return emulateRegistrationReadinfo(c, logger, baseID, token)
	case "stored":
		return emulateRegistrationStored(c, logger, baseID, token)
	default:
		logger.Warnf("Registration emulation: unknown command %q", command)
		return c.String(http.StatusOK, "")
	}
}

// emulateRegistrationConnect возвращает капчу регистрации (из локального кэша
// либо скачанную с register.kerio.com). Если капча недоступна — пустой ответ
// с кодом 500 в заголовке (клиент повторяет запрос).
func emulateRegistrationConnect(c echo.Context, cfg *config.Config, logger *logrus.Logger) error {
	captchaPath := filepath.Join("mirror", "registration", "security_image")
	data, err := os.ReadFile(captchaPath)
	valid := err == nil && len(data) > 1000 &&
		bytes.Contains(data, []byte("security_image")) &&
		bytes.Contains(data, []byte("image_signature")) &&
		bytes.Contains(data, []byte("show_image"))
	if !valid {
		logger.Info("Registration emulation: captcha missing, fetching from register.kerio.com")
		data, err = fetchRegistrationCaptcha(cfg)
		if err != nil || len(data) <= 1000 {
			logger.Warn("Registration emulation: captcha unavailable, returning internal error")
			c.Response().Header().Set("X-Kerio-Token", "")
			c.Response().Header().Set("X-Kerio-Reply-Code", "500")
			c.Response().Header().Set("X-Kerio-Reply-Message", "Internal Server Error")
			return c.String(http.StatusOK, "")
		}
		if mkErr := os.MkdirAll(filepath.Dir(captchaPath), 0o755); mkErr == nil {
			if writeErr := os.WriteFile(captchaPath, data, 0o644); writeErr != nil {
				logger.Warnf("Registration emulation: failed to cache captcha: %v", writeErr)
			}
		}
	}
	c.Response().Header().Set("X-Kerio-Token", "ac561fb1a7c3627c62f561db9bdebba8")
	c.Response().Header().Set("X-Kerio-Reply-Code", "200")
	c.Response().Header().Set("X-Kerio-Reply-Message", "OK")
	return c.Blob(http.StatusOK, "application/x-kerio-signed-png", data)
}

// emulateRegistrationLookup возвращает лицензионные данные Kerio Control.
func emulateRegistrationLookup(c echo.Context, logger *logrus.Logger, baseID, token string) error {
	expiry := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	users := "Kerio Control server"
	if envBool("KERIO_REGISTRATION_FORCE_UNLIMITED", true) {
		users = "UNLIMITED"
	}
	body := fmt.Sprintf("base_id: %s\ntype: Server\nusers: %s\nexpires: %s\ntotal_users: UNLIMITED\nedu_version: 0\nextensions: Kerio Antivirus for Kerio Control server,Kerio Web Filter server\nlicense_update: 0\nproduct: Kerio Control\ncompany: GFI Software\nreg_type: TRIAL\ndwn_trial_expires: %s\n", baseID, users, expiry, expiry)
	logger.Infof("Registration emulation: lookup for base_id=%q (users=%s, expires=%s)", baseID, users, expiry)
	c.Response().Header().Set("X-Kerio-Token", token)
	c.Response().Header().Set("X-Kerio-Reply-Code", "200")
	c.Response().Header().Set("X-Kerio-Reply-Message", "OK")
	c.Response().Header().Set("Content-Type", "application/x-kerio-registration")
	return c.String(http.StatusOK, body)
}

// emulateRegistrationReadinfo возвращает профиль регистрации Kerio Control.
func emulateRegistrationReadinfo(c echo.Context, logger *logrus.Logger, baseID, token string) error {
	expiry := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	users := "Kerio Control server"
	if envBool("KERIO_REGISTRATION_FORCE_UNLIMITED", true) {
		users = "UNLIMITED"
	}
	body := "company:\nperson:\naddress:\ncity:\nzipcode:\ncountry:\nphone:\nemail:\nwebsite:\nos: 2\nlang_id: en\ncomment:\neduinfo:\nstate:\nico:\nserialnumber:\nreseller_company:\nreseller_address:\nreseller_city:\nreseller_phone:\nreseller_email:\n" +
		fmt.Sprintf("expires: %s\n", expiry) +
		fmt.Sprintf("users: %s\n", users) +
		fmt.Sprintf("addon_list[]: %s;Server;Kerio Control server\n", baseID) +
		"show_questions: 0"
	logger.Infof("Registration emulation: readinfo for base_id=%q", baseID)
	c.Response().Header().Set("X-Kerio-Token", token)
	c.Response().Header().Set("X-Kerio-Reply-Code", "200")
	c.Response().Header().Set("X-Kerio-Reply-Message", "OK, registration data follows")
	c.Response().Header().Set("Content-Type", "application/x-kerio-registration")
	return c.String(http.StatusOK, body)
}

// emulateRegistrationStored подтверждает сохранение base_id.
func emulateRegistrationStored(c echo.Context, logger *logrus.Logger, baseID, token string) error {
	logger.Infof("Registration emulation: stored base_id=%q", baseID)
	c.Response().Header().Set("X-Kerio-Token", token)
	c.Response().Header().Set("X-Kerio-Reply-Code", "200")
	c.Response().Header().Set("X-Kerio-Reply-Message", "OK, verified")
	return c.String(http.StatusOK, fmt.Sprintf("base_id: %s", baseID))
}

// fetchRegistrationCaptcha скачивает капчу регистрации с register.kerio.com
// (формат multipart, как в референсной Python-реализации).
func fetchRegistrationCaptcha(cfg *config.Config) ([]byte, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	fields := map[string]string{
		"command":          "connect",
		"host_id":          randomMAC(),
		"product_code":     "KWF",
		"type":             "image/png",
		"protocol_version": "21",
		"lang_id":          "",
		"show_image":       "0",
		"product_version":  "0.0.0..0",
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	body, status, err := upstreamBytes(cfg, http.MethodPost, "https://register.kerio.com/registration/LD.php", buf.Bytes(), map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"User-Agent":   "Kerio License Downloader (LicenseManager)",
		"Accept":       "*/*",
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("captcha upstream status %d", status)
	}
	return body, nil
}

// randomMAC генерирует случайный unicast MAC-адрес в формате XX:XX:XX:XX:XX:XX.
func randomMAC() string {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		raw = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	}
	raw[0] &= 0xFE
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%02X", raw[i])
	}
	return strings.Join(parts, ":")
}

func vendorUpstream(cfg *config.Config, service string) string {
	if service == "antispam" {
		if v := strings.TrimSpace(os.Getenv("KERIO_ANTISPAM_UPSTREAM")); v != "" {
			return v
		}
		return "https://upgrade.bitdefender.com"
	}
	if v := strings.TrimSpace(os.Getenv("KERIO_ANTIVIRUS_UPSTREAM")); v != "" {
		return v
	}
	if cfg.BitdefenderProxyBaseURL != "" {
		return cfg.BitdefenderProxyBaseURL
	}
	return "https://upgrade.bitdefender.com"
}

var errCDNLicenseInvalid = errors.New("Kerio CDN: invalid or expired product license")

func discoverKerioCDN(cfg *config.Config, version string) (string, error) {
	if cfg.GetLicenseNumber() == "" {
		return "", errors.New("license number is missing")
	}
	u, _ := url.Parse("https://bdupdate.kerio.com/update.php")
	q := u.Query()
	q.Set("id", cfg.GetLicenseNumber())
	q.Set("product", "KWF")
	q.Set("version", version)
	u.RawQuery = q.Encode()
	body, status, err := upstreamBytes(cfg, http.MethodGet, u.String(), nil, map[string]string{"Host": "bdupdate.kerio.com", "User-Agent": "Kerio Updater"})
	if err != nil {
		return "", fmt.Errorf("CDN lookup failed (network error): %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("CDN lookup failed (HTTP %d): %s", status, strings.TrimSpace(string(body)))
	}
	text := strings.TrimSpace(string(body))
	if strings.Contains(text, "Invalid product license") || strings.Contains(text, "Maintenance expired") {
		return "", fmt.Errorf("%w (%s)", errCDNLicenseInvalid, text)
	}
	if !strings.HasPrefix(text, "THDdir=") {
		return "", fmt.Errorf("unexpected CDN response: %s", text)
	}
	return strings.TrimRight(strings.TrimPrefix(text, "THDdir="), "/"), nil
}

// notifyCDNError логирует ошибку CDN и отправляет уведомление в Telegram,
// если включены уведомления об ошибках.
func notifyCDNError(cfg *config.Config, logger *logrus.Logger, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logger.Errorf("Antivirus CDN: %s", msg)
	if cfg.TelegramNotifyOnError {
		if err := telegram.New(cfg).NotifyError("Antivirus CDN error: " + msg); err != nil {
			logger.Warnf("Telegram notification failed: %v", err)
		}
	}
}

func upstreamBytes(cfg *config.Config, method, target string, body []byte, headers map[string]string) ([]byte, int, error) {
	b, status, _, err := upstreamResponse(cfg, method, target, body, headers)
	return b, status, err
}

func upstreamResponse(cfg *config.Config, method, target string, body []byte, headers map[string]string) ([]byte, int, http.Header, error) {
	client, err := utils.CreateHTTPClient(cfg.ProxyURL, 300*time.Second)
	if err != nil {
		return nil, 0, nil, err
	}
	var last error
	for attempt := 0; attempt <= maxInt(cfg.RetryCount, 1); attempt++ {
		req, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			return nil, 0, nil, err
		}
		for k, v := range headers {
			if v != "" {
				req.Header.Set(k, v)
			}
		}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			data, readErr := io.ReadAll(resp.Body)
			return data, resp.StatusCode, resp.Header.Clone(), readErr
		}
		last = err
		if attempt < cfg.RetryCount {
			time.Sleep(time.Duration(maxInt(cfg.RetryDelaySeconds, 1)) * time.Second)
		}
	}
	return nil, 0, nil, last
}

func downloadAtomic(cfg *config.Config, target, destination string, headers map[string]string) error {
	data, status, err := upstreamBytes(cfg, http.MethodGet, target, nil, headers)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("upstream status %d", status)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".download-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, destination)
}

func safeJoin(root, rel string) (string, error) {
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target, err := filepath.Abs(filepath.Join(base, filepath.Clean(rel)))
	if err != nil {
		return "", err
	}
	r, err := filepath.Rel(base, target)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes root")
	}
	return target, nil
}

func parseMajor(v string) (int, error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) == 0 || parts[0] == "" {
		return 0, errors.New("invalid version")
	}
	return strconv.Atoi(parts[0])
}

func parseKerioUpdate(text string) (int, string, error) {
	var version int
	var link string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "0":
			parts := strings.Split(value, ".")
			if len(parts) > 1 {
				version, _ = strconv.Atoi(parts[len(parts)-1])
			}
		case "full":
			link = value
		}
	}
	if version == 0 {
		return 0, "", errors.New("version missing")
	}
	return version, link, nil
}

func publicBaseURL(c echo.Context) string {
	if configured := strings.TrimRight(strings.TrimSpace(os.Getenv("KERIO_PUBLIC_BASE_URL")), "/"); configured != "" {
		return configured
	}
	host := c.Request().Host
	if !regexp.MustCompile(`^[A-Za-z0-9.\-\[\]:]+$`).MatchString(host) {
		host = "kerio-updates-mirror.local"
	}
	scheme := c.Request().Header.Get("X-Forwarded-Proto")
	if scheme != "https" {
		scheme = "http"
	}
	return scheme + "://" + host
}

func metadataTTL() time.Duration {
	seconds, _ := strconv.Atoi(os.Getenv("KERIO_METADATA_TTL_SECONDS"))
	if seconds <= 0 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

func cacheExpired(file string, ttl time.Duration) bool {
	info, err := os.Stat(file)
	return err != nil || time.Since(info.ModTime()) >= ttl
}

func removeVersionSiblings(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, "versions.*"))
	if err != nil {
		return err
	}
	for _, file := range matches {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func lockCache(key string) func() {
	value, _ := cacheLocks.LoadOrStore(key, &sync.Mutex{})
	m := value.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func writeAtomicText(file, text string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func versionNumbers(v string) []int {
	re := regexp.MustCompile(`\d+`)
	values := re.FindAllString(v, -1)
	result := make([]int, 0, len(values))
	for _, value := range values {
		n, _ := strconv.Atoi(value)
		result = append(result, n)
	}
	return result
}

func compareVersion(a, b string) int {
	aa, bb := versionNumbers(a), versionNumbers(b)
	for i := 0; i < maxInt(len(aa), len(bb)); i++ {
		av, bv := 0, 0
		if i < len(aa) {
			av = aa[i]
		}
		if i < len(bb) {
			bv = bb[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		switch strings.ToLower(key) {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = json.Valid
