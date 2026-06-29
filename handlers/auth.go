package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"html/template"
	"net/http"
	"strings"
	"time"

	"kerio-mirror-go/config"

	"github.com/labstack/echo/v4"
)

const (
	adminSessionCookieName = "kerio_mirror_admin"
	languageCookieName     = "kerio_mirror_lang"
	adminSessionTTL        = 24 * time.Hour
	defaultAdminToken      = "admin"
	defaultLanguage        = "uk"
)

var crawlerUserAgentParts = []string{
	"bot",
	"crawler",
	"spider",
	"slurp",
	"preview",
	"facebookexternalhit",
	"telegrambot",
	"whatsapp",
	"discordbot",
	"curl",
	"wget",
}

func adminToken(cfg *config.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.AdminToken) == "" {
		return defaultAdminToken
	}
	return cfg.AdminToken
}

func validAdminToken(configuredToken, providedToken string) bool {
	configuredToken = strings.TrimSpace(configuredToken)
	providedToken = strings.TrimSpace(providedToken)
	if configuredToken == "" {
		configuredToken = defaultAdminToken
	}
	if providedToken == "" {
		return false
	}
	if len(configuredToken) != len(providedToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configuredToken), []byte(providedToken)) == 1
}

func adminSessionValue(token string) string {
	sum := sha256.Sum256([]byte("kerio-mirror-go-admin-session:" + token))
	return hex.EncodeToString(sum[:])
}

func hasValidAdminSession(c echo.Context, token string) bool {
	cookie, err := c.Cookie(adminSessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	expected := adminSessionValue(token)
	if len(cookie.Value) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expected)) == 1
}

func isHTTPSRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setAdminSessionCookie(c echo.Context, token string) {
	c.SetCookie(&http.Cookie{
		Name:     adminSessionCookieName,
		Value:    adminSessionValue(token),
		Path:     "/",
		Expires:  time.Now().Add(adminSessionTTL),
		MaxAge:   int(adminSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPSRequest(c.Request()),
	})
}

func clearAdminSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPSRequest(c.Request()),
	})
}

func requireAdminAuth(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if hasValidAdminSession(c, adminToken(cfg)) {
				return next(c)
			}
			return c.Redirect(http.StatusSeeOther, "/login")
		}
	}
}

func generateAdminToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func isCrawlerUserAgent(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	for _, part := range crawlerUserAgentParts {
		if strings.Contains(ua, part) {
			return true
		}
	}
	return false
}

func blankCrawlerPage(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderContentType, "text/html; charset=utf-8")
	return c.String(http.StatusOK, "<!doctype html><html><body></body></html>")
}

func rootHandler(cfg *config.Config, embeddedFiles embed.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		if isCrawlerUserAgent(c.Request().UserAgent()) {
			return blankCrawlerPage(c)
		}
		if hasValidAdminSession(c, adminToken(cfg)) {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}
		return renderLogin(c, embeddedFiles, "")
	}
}

func loginPageHandler(cfg *config.Config, embeddedFiles embed.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		if hasValidAdminSession(c, adminToken(cfg)) {
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}
		return renderLogin(c, embeddedFiles, "")
	}
}

func loginSubmitHandler(cfg *config.Config, embeddedFiles embed.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		if validAdminToken(adminToken(cfg), c.FormValue("token")) {
			setAdminSessionCookie(c, adminToken(cfg))
			return c.Redirect(http.StatusSeeOther, "/dashboard")
		}
		return renderLogin(c, embeddedFiles, "Неправильний токен або пароль")
	}
}

func logoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		clearAdminSessionCookie(c)
		return c.Redirect(http.StatusSeeOther, "/login")
	}
}

func renderLogin(c echo.Context, embeddedFiles embed.FS, errorMessage string) error {
	t, err := template.ParseFS(embeddedFiles, "templates/login.html")
	if err != nil {
		return c.String(http.StatusInternalServerError, "Template file error: "+err.Error())
	}
	c.Response().Header().Set(echo.HeaderContentType, "text/html; charset=utf-8")
	return t.Execute(c.Response(), map[string]string{
		"Error":       errorMessage,
		"ServiceName": "Kerio Mirror Go",
	})
}

func normalizeLanguage(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "en":
		return "en"
	case "uk", "ua":
		return "uk"
	default:
		return ""
	}
}

func selectDashboardLanguage(c echo.Context) string {
	if lang := normalizeLanguage(c.QueryParam("lang")); lang != "" {
		c.SetCookie(&http.Cookie{
			Name:     languageCookieName,
			Value:    lang,
			Path:     "/",
			Expires:  time.Now().Add(365 * 24 * time.Hour),
			MaxAge:   365 * 24 * 60 * 60,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   isHTTPSRequest(c.Request()),
		})
		return lang
	}
	if cookie, err := c.Cookie(languageCookieName); err == nil {
		if lang := normalizeLanguage(cookie.Value); lang != "" {
			return lang
		}
	}
	return defaultLanguage
}

func dashboardText(lang string) map[string]string {
	en := map[string]string{
		"Dashboard":             "Dashboard",
		"CurrentTime":           "Current time",
		"LastUpdate":            "Last update",
		"NextScheduled":         "Next scheduled",
		"Daily":                 "daily",
		"ActiveComponents":      "Active Components",
		"SuccessfulUpdates":     "Successful Updates",
		"SystemHealth":          "System Health",
		"DatabaseStatus":        "Database Status",
		"IDSDatabases":          "IDS Databases",
		"AntivirusDatabase":     "Antivirus Database",
		"ThreatIntelligence":    "Threat Intelligence",
		"Configuration":         "Configuration",
		"System":                "System",
		"Database":              "Database",
		"LogPath":               "Log Path",
		"Proxy":                 "Proxy",
		"NotConfigured":         "Not configured",
		"License":               "License",
		"Configure":             "Configure",
		"RetryPolicy":           "Retry Policy",
		"RetryCount":            "Retry Count",
		"RetryDelay":            "Retry Delay",
		"DataSources":           "Data Sources",
		"ManualUpdate":          "Manual Update",
		"ViewLogs":              "View Logs",
		"Settings":              "Settings",
		"Logout":                "Logout",
		"Disabled":              "Disabled",
		"ProxyMode":             "Proxy Mode",
		"MirrorMode":            "Mirror Mode",
		"PreloadMode":           "Preload Mode",
		"OnDemand":              "On-Demand",
		"SnortTemplateFailed":   "Snort template update failed",
		"PoweredBy":             "Powered by Go & Bootstrap",
		"Language":              "Language",
		"Ukrainian":             "Українська",
		"English":               "English",
		"LicenseNotConfigured":  "Not configured",
		"ConfigureLicenseTitle": "Configure",
	}
	if lang == "en" {
		return en
	}
	return map[string]string{
		"Dashboard":             "Панель",
		"CurrentTime":           "Поточний час",
		"LastUpdate":            "Останнє оновлення",
		"NextScheduled":         "Наступне за розкладом",
		"Daily":                 "щодня",
		"ActiveComponents":      "Активні компоненти",
		"SuccessfulUpdates":     "Успішні оновлення",
		"SystemHealth":          "Стан системи",
		"DatabaseStatus":        "Стан баз",
		"IDSDatabases":          "Бази IDS",
		"AntivirusDatabase":     "Антивірусна база",
		"ThreatIntelligence":    "Threat Intelligence",
		"Configuration":         "Конфігурація",
		"System":                "Система",
		"Database":              "База даних",
		"LogPath":               "Шлях до логів",
		"Proxy":                 "Проксі",
		"NotConfigured":         "Не налаштовано",
		"License":               "Ліцензія",
		"Configure":             "Налаштувати",
		"RetryPolicy":           "Політика повторів",
		"RetryCount":            "Кількість повторів",
		"RetryDelay":            "Затримка повтору",
		"DataSources":           "Джерела даних",
		"ManualUpdate":          "Оновити вручну",
		"ViewLogs":              "Переглянути логи",
		"Settings":              "Налаштування",
		"Logout":                "Вийти",
		"Disabled":              "Вимкнено",
		"ProxyMode":             "Режим проксі",
		"MirrorMode":            "Режим дзеркала",
		"PreloadMode":           "Попереднє завантаження",
		"OnDemand":              "На вимогу",
		"SnortTemplateFailed":   "Не вдалося оновити Snort template",
		"PoweredBy":             "Працює на Go та Bootstrap",
		"Language":              "Мова",
		"Ukrainian":             "Українська",
		"English":               "English",
		"LicenseNotConfigured":  "Не налаштовано",
		"ConfigureLicenseTitle": "Налаштувати",
	}
}
