package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/webui"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	var (
		configPath   string
		listen       string
		logLevel     string
		printVer     bool
		hashPassword bool
		password     string
	)

	flag.StringVar(&configPath, "config", "/etc/crowdsec/webui.yaml", "path to the configuration file")
	flag.StringVar(&listen, "listen", "", "override the listen address")
	flag.StringVar(&logLevel, "log-level", "info", "log level (trace, debug, info, warn, error)")
	flag.BoolVar(&printVer, "version", false, "print version and exit")
	flag.BoolVar(&hashPassword, "hash-password", false, "read a password and print its bcrypt hash")
	flag.StringVar(&password, "password", "", "password to hash together with -hash-password")

	flag.Parse()

	if printVer {
		fmt.Fprintf(os.Stdout, "cswebui %s\n", version)
		return
	}

	if hashPassword {
		if err := printPasswordHash(password); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		return
	}

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %q: %s\n", logLevel, err)
		os.Exit(1)
	}

	logger := logrus.New()
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	cfg, err := webui.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if listen != "" {
		cfg.Listen = listen
	}

	server, err := webui.NewServer(cfg, logger, version)
	if err != nil {
		logger.Errorf("building server: %s", err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)

	go func() {
		logger.Infof("cswebui %s listening on http://%s", version, cfg.Listen)
		errCh <- httpServer.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		logger.Infof("received %s, shutting down", sig)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("server error: %s", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Errorf("graceful shutdown failed: %s", err)
	}

	if err := server.Close(); err != nil {
		logger.Warnf("closing database: %s", err)
	}
}

func printPasswordHash(password string) error {
	if password == "" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Password: ")

			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)

			if err != nil {
				return fmt.Errorf("reading password: %w", err)
			}

			password = string(raw)
		} else {
			data, err := os.ReadFile("/dev/stdin")
			if err != nil {
				return fmt.Errorf("reading password from stdin: %w", err)
			}

			password = strings.TrimSpace(string(data))
		}
	}

	hash, err := webui.HashPassword(password)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, hash)

	return nil
}
