package handlers

import (
	"embed"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"kerio-mirror-go/config"
	"kerio-mirror-go/logging"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func RegisterAdminRoutes(e *echo.Echo, cfg *config.Config, logger *logrus.Logger, embeddedFiles embed.FS) {
	protected := requireAdminAuth(cfg)

	e.GET("/", rootHandler(cfg, embeddedFiles))
	e.GET("/login", loginPageHandler(cfg, embeddedFiles))
	e.POST("/login", loginSubmitHandler(cfg, embeddedFiles))
	e.GET("/logout", logoutHandler())
	e.GET("/dashboard", protected(dashboardPageHandler(embeddedFiles)))
	e.GET("/dushboard", protected(func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/dashboard")
	}))

	e.GET("/settings", protected(settingsPageWithAuthHandler(cfg, embeddedFiles)))
	e.POST("/settings", protected(settingsPageWithAuthHandler(cfg, embeddedFiles)))
	e.GET("/logs", protected(serveFileHandler(cfg.LogPath, embeddedFiles)))
	e.GET("/logs/raw", protected(serveRawLogHandler(cfg.LogPath)))
	e.GET("/logs/full_raw", protected(serveFullRawLogHandler(cfg.LogPath)))
	e.GET("/update", protected(updateHandler(cfg, logger)))

	e.GET("/getkey.php", webFilterKeyHandler(cfg))
	e.GET("/update.php", updateKerioHandler(cfg, logger))
	e.GET("/check_update/", shieldMatrixCheckUpdateHandler(cfg, logger))
	e.GET("/favicon.ico", func(c echo.Context) error {
		data, err := embeddedFiles.ReadFile("favicon.ico")
		if err != nil {
			return c.String(http.StatusNotFound, "favicon.ico not found in embedded files")
		}
		return c.Blob(http.StatusOK, "image/x-icon", data)
	})
	e.GET("/control-update/*", controlUpdateHandler(logger))
	e.GET("/matrix/*", matrixHandler(logger))
	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(embeddedFiles))))
	e.GET("/*", customFilesHandlerOrFallback(cfg, logger))
}

func dashboardPageHandler(embeddedFiles embed.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger, ok := c.Get("logger").(*logrus.Logger)
		if !ok {
			return c.String(http.StatusInternalServerError, "Internal Server Error")
		}
		logger.Infof("Web access: %s %s from %s", c.Request().Method, c.Request().URL.Path, c.RealIP())
		cfg, ok := c.Get("config").(*config.Config)
		if !ok {
			return c.String(http.StatusInternalServerError, "Internal Server Error")
		}
		status, err := getDashboardStatus(cfg)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Failed to load status")
		}
		lang := selectDashboardLanguage(c)
		t, err := template.ParseFS(embeddedFiles, "templates/dashboard.html")
		if err != nil {
			return c.String(http.StatusInternalServerError, "Template file error: "+err.Error())
		}
		c.Response().Header().Set(echo.HeaderContentType, "text/html; charset=utf-8")
		return t.Execute(c.Response(), struct {
			*DashboardStatus
			Lang string
			Text map[string]string
		}{
			DashboardStatus: status,
			Lang:            lang,
			Text:            dashboardText(lang),
		})
	}
}

func settingsPageWithAuthHandler(cfg *config.Config, embeddedFiles embed.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger, ok := c.Get("logger").(*logrus.Logger)
		if !ok {
			return c.String(http.StatusInternalServerError, "Internal Server Error")
		}
		logger.Infof("Web access: %s %s from %s", c.Request().Method, c.Request().URL.Path, c.RealIP())
		message := ""
		if c.Request().Method == http.MethodPost {
			cfg.ScheduleTime = c.FormValue("ScheduleTime")
			cfg.DatabasePath = c.FormValue("DatabasePath")
			cfg.LogPath = c.FormValue("LogPath")
			cfg.ProxyURL = c.FormValue("ProxyURL")
			cfg.LicenseNumber = c.FormValue("LicenseNumber")
			cfg.WebFilterAPI = c.FormValue("WebFilterApi")
			cfg.GeoIP4URL = c.FormValue("GeoIP4Url")
			cfg.GeoIP6URL = c.FormValue("GeoIP6Url")
			cfg.GeoLocURL = c.FormValue("GeoLocUrl")
			cfg.RetryCount, _ = strconv.Atoi(c.FormValue("RetryCount"))
			cfg.RetryDelaySeconds, _ = strconv.Atoi(c.FormValue("RetryDelaySeconds"))
			cfg.LogLevel = c.FormValue("LogLevel")
			cfg.IDSURL = c.FormValue("IDSUrl")

			if c.FormValue("GenerateAdminToken") == "true" {
				token, err := generateAdminToken()
				if err != nil {
					logger.Errorf("Failed to generate admin token: %v", err)
					return c.String(http.StatusInternalServerError, "Failed to generate admin token")
				}
				cfg.AdminToken = token
				message = "Налаштування збережено, новий admin token згенеровано."
			} else {
				cfg.AdminToken = strings.TrimSpace(c.FormValue("AdminToken"))
				if cfg.AdminToken == "" {
					cfg.AdminToken = defaultAdminToken
				}
				message = "Налаштування успішно оновлено."
			}

			bitdefUrlsRaw := c.FormValue("BitdefenderUrls")
			cfg.BitdefenderURLs = nil
			for _, line := range strings.Split(bitdefUrlsRaw, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					cfg.BitdefenderURLs = append(cfg.BitdefenderURLs, line)
				}
			}

			switch c.FormValue("BitdefenderMode") {
			case "mirror":
				cfg.BitdefenderMode = "mirror"
			case "proxy":
				cfg.BitdefenderMode = "proxy"
			default:
				cfg.BitdefenderMode = "disabled"
			}
			cfg.BitdefenderProxyBaseURL = c.FormValue("BitdefenderProxyBaseURL")

			customUrlsRaw := c.FormValue("CustomDownloadUrls")
			cfg.CustomDownloadURLs = nil
			for _, line := range strings.Split(customUrlsRaw, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					cfg.CustomDownloadURLs = append(cfg.CustomDownloadURLs, line)
				}
			}
			cfg.EnableIDS1 = c.FormValue("EnableIDS1") == "true"
			cfg.EnableIDS2 = c.FormValue("EnableIDS2") == "true"
			cfg.EnableIDS3 = c.FormValue("EnableIDS3") == "true"
			cfg.EnableIDS4 = c.FormValue("EnableIDS4") == "true"
			cfg.EnableIDS5 = c.FormValue("EnableIDS5") == "true"
			cfg.EnableSnortTemplate = c.FormValue("EnableSnortTemplate") == "true"
			cfg.SnortTemplateURL = c.FormValue("SnortTemplateURL")
			cfg.EnableShieldMatrix = c.FormValue("EnableShieldMatrix") == "true"
			cfg.ShieldMatrixBaseURL = c.FormValue("ShieldMatrixBaseURL")
			cfg.ShieldMatrixClientID = c.FormValue("ShieldMatrixClientID")
			cfg.ShieldMatrixVersion = c.FormValue("ShieldMatrixVersion")
			cfg.ShieldMatrixPreloadFiles = c.FormValue("ShieldMatrixPreloadFiles") == "true"

			allowedIPsRaw := c.FormValue("AllowedIPs")
			cfg.AllowedIPs = nil
			for _, line := range strings.Split(allowedIPsRaw, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					cfg.AllowedIPs = append(cfg.AllowedIPs, line)
				}
			}

			blockedIPsRaw := c.FormValue("BlockedIPs")
			cfg.BlockedIPs = nil
			for _, line := range strings.Split(blockedIPsRaw, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					cfg.BlockedIPs = append(cfg.BlockedIPs, line)
				}
			}

			cfg.TelegramBotToken = c.FormValue("TelegramBotToken")
			cfg.TelegramChatID = c.FormValue("TelegramChatID")
			cfg.TelegramNotifyOnError = c.FormValue("TelegramNotifyOnError") == "true"
			cfg.TelegramNotifyOnSuccess = c.FormValue("TelegramNotifyOnSuccess") == "true"
			cfg.TelegramNotifyOnStart = c.FormValue("TelegramNotifyOnStart") == "true"

			configPath, ok := c.Get("configPath").(string)
			if !ok {
				logger.Error("Config path not found in context")
				return c.String(http.StatusInternalServerError, "Internal Server Error")
			}
			if err := config.Save(cfg, configPath); err != nil {
				logger.Errorf("Failed to save config: %v", err)
				return c.String(http.StatusInternalServerError, "Failed to save config")
			}
			setAdminSessionCookie(c, adminToken(cfg))
			logging.UpdateLogLevel(logger, cfg.LogLevel)
		}

		t, err := template.ParseFS(embeddedFiles, "templates/settings.html")
		if err != nil {
			return c.String(http.StatusInternalServerError, "Template file error: "+err.Error())
		}
		c.Response().Header().Set(echo.HeaderContentType, "text/html; charset=utf-8")
		return t.Execute(c.Response(), map[string]interface{}{
			"Config":  cfg,
			"Message": message,
		})
	}
}
