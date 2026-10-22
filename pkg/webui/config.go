// Package webui implements a self-hosted web interface for a CrowdSec
// Security Engine: monitoring of alerts and decisions, manual bans, and
// configuration file editing. It talks to the local API over HTTP and needs
// no crowdsec.net account.
package webui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	DefaultListen          = "127.0.0.1:8081"
	DefaultLAPICredentials = "/etc/crowdsec/local_api_credentials.yaml"
	DefaultConfigDir       = "/etc/crowdsec"
	DefaultSessionTTL      = 12 * time.Hour
)

// Config is the cswebui configuration.
type Config struct {
	// Listen is the address the web UI listens on.
	Listen string `yaml:"listen"`
	// LAPI describes how to reach the local API.
	LAPI LAPIConfig `yaml:"lapi"`
	// Engine configures the live-reload and config editing features.
	Engine EngineConfig `yaml:"engine"`
	// Auth holds the local accounts of the web UI.
	Auth AuthConfig `yaml:"auth"`
	// Files are the configuration files (relative to engine.config_dir) that
	// may be edited through the web UI.
	Files []string `yaml:"files"`
	// Blocklist optionally points at a csblocklistd admin API.
	Blocklist *BlocklistConfig `yaml:"blocklist"`
	// Data configures optional read-only data sources.
	Data DataConfig `yaml:"data"`

	tlsCert string
	tlsKey  string
}

// LAPIConfig holds the local API endpoint and credentials.
type LAPIConfig struct {
	// URL of the local API (defaults to the url field of the credentials file).
	URL string `yaml:"url"`
	// CredentialsPath is a machine credentials file as written by cscli.
	CredentialsPath string `yaml:"credentials_path"`
	// Login and Password override the credentials file (mostly for tests).
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	// InsecureSkipVerify disables TLS verification for the LAPI connection.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// EngineConfig configures how the web UI reloads the engine.
type EngineConfig struct {
	// ConfigDir is the directory holding config.yaml, acquis.yaml, ...
	ConfigDir string `yaml:"config_dir"`
	// ReloadCommand is executed to apply configuration changes, e.g.
	// ["systemctl", "reload", "crowdsec"] or ["cscli"] with a custom wrapper.
	ReloadCommand []string `yaml:"reload_command"`
	// PIDFile, when set, is used to send SIGHUP to the engine instead of
	// running ReloadCommand.
	PIDFile string `yaml:"pid_file"`
}

// AuthConfig holds the web UI accounts.
type AuthConfig struct {
	Users []User `yaml:"users"`
	// SessionTTL is how long a login stays valid.
	SessionTTL string `yaml:"session_ttl"`
	// SecureCookie marks the session cookie Secure (enable behind HTTPS).
	SecureCookie bool `yaml:"secure_cookie"`
}

// User is a local web UI account. PasswordHash must be a bcrypt hash, as
// produced by `cswebui -hash-password`.
type User struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// DataConfig configures the extra read-only data sources: the LAPI SQLite
// database (machines, bouncers, geo/AS aggregates) and the engine's
// Prometheus endpoint (parsers, buckets, acquisition, LAPI routes).
type DataConfig struct {
	// DBPath is the SQLite database of the local API. When empty, db_config.db_path
	// from the engine's config.yaml is used.
	DBPath string `yaml:"db_path"`
	// MetricsURL is the Prometheus exposition endpoint of the engine.
	MetricsURL string `yaml:"metrics_url"`
}

// BlocklistConfig points the web UI at a csblocklistd admin API, so that the
// shared blocklist can be managed from the same interface.
type BlocklistConfig struct {
	AdminURL   string `yaml:"admin_url"`
	AdminToken string `yaml:"admin_token"`
}

// LoadConfig reads, defaults and validates a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	cfg := &Config{}

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)

	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if err := cfg.SetDefaults(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SetDefaults fills in unset values and validates the result.
func (c *Config) SetDefaults() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}

	if c.LAPI.CredentialsPath == "" {
		c.LAPI.CredentialsPath = DefaultLAPICredentials
	}

	if c.Engine.ConfigDir == "" {
		c.Engine.ConfigDir = DefaultConfigDir
	}

	if len(c.Files) == 0 {
		c.Files = []string{"acquis.yaml", "profiles.yaml", "config.yaml"}
	}

	if c.Data.MetricsURL == "" {
		c.Data.MetricsURL = "http://127.0.0.1:6060/metrics"
	}

	if c.Auth.SessionTTL == "" {
		c.Auth.SessionTTL = DefaultSessionTTL.String()
	}

	if _, err := time.ParseDuration(c.Auth.SessionTTL); err != nil {
		return fmt.Errorf("invalid auth.session_ttl %q: %w", c.Auth.SessionTTL, err)
	}

	if len(c.Auth.Users) == 0 {
		return errors.New("no user configured: add auth.users with a username and a bcrypt password_hash")
	}

	for _, user := range c.Auth.Users {
		if user.Username == "" {
			return errors.New("auth.users: empty username")
		}

		if _, err := bcrypt.Cost([]byte(user.PasswordHash)); err != nil {
			return fmt.Errorf("auth.users[%s]: password_hash is not a bcrypt hash: %w", user.Username, err)
		}
	}

	if c.Blocklist != nil && c.Blocklist.AdminURL == "" {
		return errors.New("blocklist.admin_url is required when blocklist is configured")
	}

	return nil
}

// SessionTTLDuration returns the parsed session TTL.
func (c *Config) SessionTTLDuration() time.Duration {
	ttl, err := time.ParseDuration(c.Auth.SessionTTL)
	if err != nil {
		return DefaultSessionTTL
	}

	return ttl
}

// Credentials returns the LAPI URL, login and password, reading the machine
// credentials file when the config does not override them.
func (c *Config) Credentials() (string, string, string, error) {
	url, login, password := c.LAPI.URL, c.LAPI.Login, c.LAPI.Password

	if login == "" || password == "" {
		data, err := os.ReadFile(c.LAPI.CredentialsPath)
		if err != nil {
			if os.IsNotExist(err) {
				return "", "", "", fmt.Errorf(
					"no LAPI credentials: %s does not exist, run 'cscli machines add cswebui --file %s'",
					c.LAPI.CredentialsPath, c.LAPI.CredentialsPath)
			}

			return "", "", "", fmt.Errorf("reading LAPI credentials: %w", err)
		}

		var credentials struct {
			URL      string `yaml:"url"`
			Login    string `yaml:"login"`
			Password string `yaml:"password"`
		}

		if err := yaml.Unmarshal(data, &credentials); err != nil {
			return "", "", "", fmt.Errorf("parsing LAPI credentials: %w", err)
		}

		if url == "" {
			url = credentials.URL
		}

		login = credentials.Login
		password = credentials.Password
	}

	if url == "" || login == "" || password == "" {
		return "", "", "", fmt.Errorf(
			"incomplete LAPI credentials in %s (url, login and password are required)", c.LAPI.CredentialsPath)
	}

	return url, login, password, nil
}

// HashPassword returns a bcrypt hash of password.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}

	return string(hash), nil
}
