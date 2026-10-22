package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/blocklistserver"
	"github.com/sirupsen/logrus"
)

var version = "dev"

func main() {
	var (
		configPath  string
		listen      string
		dbPath      string
		logLevel    string
		printVer    bool
		genToken    bool
		adminToken  string
		registerTok string
	)

	flag.StringVar(&configPath, "config", "/etc/crowdsec/blocklist.yaml", "path to the configuration file")
	flag.StringVar(&listen, "listen", "", "override the listen address")
	flag.StringVar(&dbPath, "db", "", "override the database path")
	flag.StringVar(&logLevel, "log-level", "info", "log level (trace, debug, info, warn, error)")
	flag.BoolVar(&printVer, "version", false, "print version and exit")
	flag.BoolVar(&genToken, "gen-admin-token", false, "generate an admin token and exit")
	flag.StringVar(&adminToken, "admin-token", "", "override the admin token")
	flag.StringVar(&registerTok, "registration-token", "", "override the registration token")

	flag.Parse()
	os.Exit(run(configPath, listen, dbPath, logLevel, printVer, genToken, adminToken, registerTok))
}

func run(configPath, listen, dbPath, logLevel string, printVer, genToken bool, adminToken, registerTok string) int {
	if printVer {
		fmt.Fprintf(os.Stdout, "csblocklistd %s\n", version)
		return 0
	}

	if genToken {
		token, err := blocklistserver.GenerateToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate token: %s\n", err)
			return 1
		}

		fmt.Fprintln(os.Stdout, token)
		return 0
	}

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %q: %s\n", logLevel, err)
		return 1
	}

	logger := logrus.New()
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	if listen != "" {
		cfg.Listen = listen
	}

	if dbPath != "" {
		cfg.DBPath = dbPath
	}

	if adminToken != "" {
		cfg.AdminToken = adminToken
	}

	if registerTok != "" {
		cfg.RegistrationToken = registerTok
	}

	store, err := blocklistserver.OpenStore(cfg.DBPath)
	if err != nil {
		logger.Errorf("opening database: %s", err)
		return 1
	}
	defer store.Close()

	server, err := blocklistserver.NewServer(cfg, store, logger)
	if err != nil {
		logger.Errorf("building server: %s", err)
		return 1
	}

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)

	go func() {
		if cfg.TLSCert != "" {
			logger.Infof("csblocklistd %s listening on https://%s", version, cfg.Listen)
			errCh <- httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			return
		}

		logger.Infof("csblocklistd %s listening on http://%s", version, cfg.Listen)
		errCh <- httpServer.ListenAndServe()
	}()

	if cfg.AdminToken == "" {
		logger.Warn("no admin_token configured: /admin/v1 is restricted to loopback clients")
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		logger.Infof("received %s, shutting down", sig)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("server error: %s", err)
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Errorf("graceful shutdown failed: %s", err)
	}
	return 0
}

func loadConfig(path string) (*blocklistserver.Config, error) {
	cfg, err := blocklistserver.LoadConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Allow starting with flags only, using the defaults.
			cfg = &blocklistserver.Config{}
			if err := cfg.SetDefaults(); err != nil {
				return nil, err
			}

			return cfg, nil
		}

		return nil, err
	}

	return cfg, nil
}
