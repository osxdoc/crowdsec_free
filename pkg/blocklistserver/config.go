// Package blocklistserver implements a self-hosted replacement for the
// CrowdSec Central API (CAPI) subset used to exchange blocklists between
// Security Engines.
//
// Engines point the "url" of their online_api_credentials.yaml at this server
// and register with `cscli capi register`. From then on they push their alerts
// and pull a shared decision stream, no crowdsec.net account involved.
package blocklistserver

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListen            = "127.0.0.1:8082"
	DefaultDBPath            = "/var/lib/crowdsec/blocklist.db"
	DefaultCommunityScenario = "crowdsec/community-blocklist"
	DefaultTokenTTL          = 24 * time.Hour
	DefaultDuration          = "4h"
	DefaultMaxAlerts         = 100
	DefaultMaxDecisions      = 1000
)

// Config configures the blocklist server.
type Config struct {
	// Listen is the address the HTTP API listens on.
	Listen string `yaml:"listen"`
	// DBPath is the SQLite database holding machines and decisions.
	DBPath string `yaml:"db_path"`
	// AdminToken protects the /admin/v1 endpoints. When empty, they are only
	// reachable from loopback.
	AdminToken string `yaml:"admin_token"`
	// RegistrationToken, when set, is required to register a new watcher.
	// Engines registered with `cscli capi register` cannot send it, so only
	// enable this when watchers are onboarded through the web UI.
	RegistrationToken string `yaml:"registration_token"`
	// CommunityScenario is the scenario name served to engines. Keeping the
	// CAPI default lets existing profiles and dashboards label the entries.
	CommunityScenario string `yaml:"community_scenario"`
	// TokenTTL is the lifetime of the JWTs handed out at login.
	TokenTTL string `yaml:"token_ttl"`
	// TLSCert and TLSKey enable HTTPS when both are set.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`

	Push PushConfig `yaml:"push"`

	// tokenTTL is the parsed form of TokenTTL.
	tokenTTL time.Duration
}

// PushConfig controls which alerts pushed by engines end up in the shared
// blocklist.
type PushConfig struct {
	// AcceptOrigins lists the decision origins accepted from engines.
	// Defaults to ["cscli"], i.e. manual decisions only: sharing every
	// scenario-generated decision of every instance is rarely what you want.
	AcceptOrigins []string `yaml:"accept_origins"`
	// MaxAlertsPerRequest caps the size of a pushed payload.
	MaxAlertsPerRequest int `yaml:"max_alerts_per_request"`
	// MaxDecisionsPerAlert caps the decisions read from a single alert.
	MaxDecisionsPerAlert int `yaml:"max_decisions_per_alert"`
	// DefaultDuration is used when a pushed decision has no duration.
	DefaultDuration string `yaml:"default_duration"`
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

	if c.DBPath == "" {
		c.DBPath = DefaultDBPath
	}

	if c.CommunityScenario == "" {
		c.CommunityScenario = DefaultCommunityScenario
	}

	if c.TokenTTL == "" {
		c.TokenTTL = DefaultTokenTTL.String()
	}

	ttl, err := time.ParseDuration(c.TokenTTL)
	if err != nil {
		return fmt.Errorf("invalid token_ttl %q: %w", c.TokenTTL, err)
	}

	if ttl <= 0 {
		return fmt.Errorf("token_ttl must be positive, got %s", ttl)
	}

	c.tokenTTL = ttl

	if len(c.Push.AcceptOrigins) == 0 {
		c.Push.AcceptOrigins = []string{"cscli"}
	}

	if c.Push.MaxAlertsPerRequest <= 0 {
		c.Push.MaxAlertsPerRequest = DefaultMaxAlerts
	}

	if c.Push.MaxDecisionsPerAlert <= 0 {
		c.Push.MaxDecisionsPerAlert = DefaultMaxDecisions
	}

	if c.Push.DefaultDuration == "" {
		c.Push.DefaultDuration = DefaultDuration
	}

	if _, err := ParseDuration(c.Push.DefaultDuration); err != nil {
		return fmt.Errorf("invalid push.default_duration %q: %w", c.Push.DefaultDuration, err)
	}

	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be set together")
	}

	return nil
}

// TokenTTLDuration returns the parsed token TTL.
func (c *Config) TokenTTLDuration() time.Duration {
	if c.tokenTTL == 0 {
		return DefaultTokenTTL
	}

	return c.tokenTTL
}

// AcceptsOrigin reports whether decisions with the given origin are pushed
// into the shared blocklist.
func (c *Config) AcceptsOrigin(origin string) bool {
	for _, accepted := range c.Push.AcceptOrigins {
		if strings.EqualFold(accepted, origin) {
			return true
		}
	}

	return false
}
