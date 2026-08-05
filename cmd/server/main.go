package main

import (
	"crypto/tls"
	"embed"
	"flag"
	"log"
	"net/http"
	"os"

	"kerio-mirror-go/config"
	"kerio-mirror-go/db"
	"kerio-mirror-go/handlers"
	"kerio-mirror-go/logging"
	"kerio-mirror-go/middleware"
	"kerio-mirror-go/mirror"

	"github.com/labstack/echo/v4"
)

//go:embed templates static favicon.ico
var embeddedFiles embed.FS

func main() {
	cfgPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	logger := logging.NewLogger(cfg.LogPath, cfg.LogLevel)
	logger.Info("Starting kerio-mirror-go v0.5.6")

	if err := db.Init(cfg.DatabasePath); err != nil {
		logger.Fatalf("DB init error: %v", err)
	}

	go mirror.StartScheduler(cfg, logger)

	e := echo.New()
	// Rewrites DNS-intercepted Kerio hostnames before Echo selects a route.
	e.Pre(middleware.HostRouterMiddleware())
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("config", cfg)
			c.Set("logger", logger)
			c.Set("configPath", *cfgPath)
			return next(c)
		}
	})
	e.Use(middleware.IPFilterMiddleware(cfg, logger))
	handlers.RegisterAdminRoutes(e, cfg, logger, embeddedFiles)
	handlers.RegisterDistroAdminRoutes(e, cfg, logger)

	addr := serverAddressFromEnv()
	logger.Infof("Starting HTTP server on %s", addr)

	tlsAddr := tlsServerAddressFromEnv()
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")

	if tlsCert != "" && tlsKey != "" {
		httpServer := &http.Server{Addr: addr, Handler: e}
		tlsServer := &http.Server{
			Addr:      tlsAddr,
			Handler:   e,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
		go func() {
			logger.Infof("Starting HTTPS server on %s", tlsAddr)
			if err := tlsServer.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("HTTPS server error: %v", err)
			}
		}()
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("HTTP server error: %v", err)
		}
		return
	}

	if err := e.Start(addr); err != nil {
		logger.Fatalf("HTTP server error: %v", err)
	}
}
