package webui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
)

//go:embed assets
var assetsFS embed.FS

// Server is the cswebui HTTP server.
type Server struct {
	cfg       *Config
	log       *logrus.Logger
	sessions  *sessionManager
	lapi      *apiclient.ApiClient
	blocklist *blocklistClient
	state     *StateStore
	version   string
	startedAt time.Time
	// hubMu serializes hub changes: concurrent cscli runs would race on the same
	// files and on the local API database.
	hubMu sync.Mutex
	// runCscli exists so tests can capture the arguments without running cscli.
	runCscli func(ctx context.Context, args ...string) (string, error)
}

type ctxKey string

const (
	ctxUserKey ctxKey = "user"
	ctxCSRFKey ctxKey = "csrf"
)

// NewServer builds the web UI server. It does not contact the local API yet;
// a failed connection is reported to the user instead of blocking startup.
func NewServer(cfg *Config, log *logrus.Logger, version string) (*Server, error) {
	sessions, err := newSessionManager(cfg)
	if err != nil {
		return nil, err
	}

	lapiURL, login, password, err := cfg.Credentials()
	if err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(lapiURL)
	if err != nil {
		return nil, fmt.Errorf("parsing lapi.url %q: %w", lapiURL, err)
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("lapi.url %q must include a scheme and host (for example http://127.0.0.1:8080)", lapiURL)
	}

	// The API client resolves request paths relative to the base URL, so it
	// must end with a slash.
	if !strings.HasSuffix(parsedURL.Path, "/") {
		parsedURL.Path += "/"
	}

	apiclient.InsecureSkipVerify = cfg.LAPI.InsecureSkipVerify

	lapi := apiclient.NewClient(&apiclient.Config{
		MachineID:     login,
		Password:      strfmt.Password(password),
		URL:           parsedURL,
		VersionPrefix: "v1",
		UserAgent:     "cswebui/" + version,
	})

	server := &Server{
		cfg:       cfg,
		log:       log,
		sessions:  sessions,
		lapi:      lapi,
		version:   version,
		startedAt: time.Now(),
	}

	server.runCscli = server.execCscli

	if cfg.Blocklist != nil {
		server.blocklist = newBlocklistClient(cfg.Blocklist)
	}

	if dbPath := cfg.DatabasePath(); dbPath != "" {
		state, err := OpenStateStore(dbPath)
		if err != nil {
			log.Warnf("database features disabled: %s", err)
		} else {
			server.state = state
			log.Infof("reading machines/bouncers from %s", dbPath)
		}
	} else {
		log.Info("no SQLite database configured, machine/bouncer views are disabled")
	}

	go server.checkLAPI()

	return server, nil
}

// checkLAPI logs whether the local API is reachable. A failure is not fatal:
// the engine may start after the web UI.
// Close releases the optional database handle.
func (s *Server) Close() error {
	if s.state != nil {
		return s.state.Close()
	}

	return nil
}

func (s *Server) checkLAPI() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, _, err := s.lapi.HeartBeat.Ping(ctx); err != nil {
		s.log.Warnf("local API is not reachable yet: %s", err)
		return
	}

	s.log.Info("connected to the local API")
}

// Handler returns the HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/session", s.withAuth(s.handleSession))

	mux.HandleFunc("GET /api/overview", s.withAuth(s.handleOverview))
	mux.HandleFunc("GET /api/infra", s.withAuth(s.handleInfra))
	mux.HandleFunc("GET /api/metrics", s.withAuth(s.handleMetrics))

	mux.HandleFunc("GET /api/alerts", s.withAuth(s.handleListAlerts))
	mux.HandleFunc("GET /api/alerts/{id}", s.withAuth(s.handleGetAlert))
	mux.HandleFunc("DELETE /api/alerts/{id}", s.withAuth(s.handleDeleteAlert))

	mux.HandleFunc("GET /api/decisions", s.withAuth(s.handleListDecisions))
	mux.HandleFunc("POST /api/decisions", s.withAuth(s.handleCreateDecision))
	mux.HandleFunc("DELETE /api/decisions/{id}", s.withAuth(s.handleDeleteDecision))

	mux.HandleFunc("GET /api/allowlists", s.withAuth(s.handleListAllowlists))
	mux.HandleFunc("GET /api/allowlists/{name}", s.withAuth(s.handleGetAllowlist))

	mux.HandleFunc("GET /api/config", s.withAuth(s.handleListConfig))
	mux.HandleFunc("GET /api/config/{name...}", s.withAuth(s.handleGetConfig))
	mux.HandleFunc("PUT /api/config/{name...}", s.withAuth(s.handlePutConfig))
	mux.HandleFunc("POST /api/reload", s.withAuth(s.handleReload))

	mux.HandleFunc("GET /api/hub", s.withAuth(s.handleHub))
	mux.HandleFunc("POST /api/hub/update", s.withAuth(s.handleHubAction("update")))
	mux.HandleFunc("POST /api/hub/upgrade", s.withAuth(s.handleHubAction("upgrade")))
	mux.HandleFunc("POST /api/hub/install", s.withAuth(s.handleHubAction("install")))
	mux.HandleFunc("POST /api/hub/remove", s.withAuth(s.handleHubAction("remove")))

	mux.HandleFunc("GET /api/blocklist/stats", s.withAuth(s.handleBlocklistStats))
	mux.HandleFunc("GET /api/blocklist/decisions", s.withAuth(s.handleBlocklistDecisions))
	mux.HandleFunc("POST /api/blocklist/decisions", s.withAuth(s.handleBlocklistCreate))
	mux.HandleFunc("DELETE /api/blocklist/decisions/{id}", s.withAuth(s.handleBlocklistDelete))
	mux.HandleFunc("GET /api/blocklist/machines", s.withAuth(s.handleBlocklistMachines))

	mux.HandleFunc("GET /", s.serveSPA)

	return s.securityHeaders(s.logRequests(mux))
}

// securityHeaders hardens the UI a little; the app ships no external assets.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		entry := s.log.WithFields(logrus.Fields{
			"method":  r.Method,
			"path":    r.URL.Path,
			"status":  rec.status,
			"elapsed": time.Since(start).String(),
			"remote":  r.RemoteAddr,
		})

		if rec.status >= http.StatusInternalServerError {
			entry.Error("request failed")
		} else if rec.status >= http.StatusBadRequest {
			entry.Warn("request rejected")
		} else {
			entry.Debug("request handled")
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

type errorResponse struct {
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, errorResponse{Message: fmt.Sprintf(format, args...)})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)

	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}

	return nil
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, csrf, ok := s.sessions.verify(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			header := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(header), []byte(csrf)) != 1 {
				writeError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxUserKey, user)
		ctx = context.WithValue(ctx, ctxCSRFKey, csrf)

		next(w, r.WithContext(ctx))
	}
}

func currentUser(r *http.Request) string {
	user, _ := r.Context().Value(ctxUserKey).(string)
	return user
}

func currentCSRF(r *http.Request) string {
	csrf, _ := r.Context().Value(ctxCSRFKey).(string)
	return csrf
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest

	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	token, csrf, err := s.sessions.login(req.Username, req.Password, clientIP(r))
	if err != nil {
		s.log.Warnf("failed login for %q from %s", req.Username, clientIP(r))
		writeError(w, http.StatusUnauthorized, "%s", err)
		return
	}

	s.sessions.setCookie(w, token)
	s.log.Infof("user %q logged in from %s", req.Username, clientIP(r))

	writeJSON(w, http.StatusOK, map[string]any{"user": req.Username, "csrf": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	s.sessions.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	session := map[string]any{
		"user":    currentUser(r),
		"csrf":    currentCSRF(r),
		"version": s.version,
		"uptime":  time.Since(s.startedAt).Truncate(time.Second).String(),
		"features": map[string]bool{
			"blocklist": s.blocklist != nil,
		},
		"lapi_url": s.cfg.LAPI.URL,
	}

	writeJSON(w, http.StatusOK, session)
}

// serveSPA serves the embedded single page application.
func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	staticFS, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	// Unknown API routes must 404 instead of returning the SPA shell.
	if strings.HasPrefix(path, "api/") {
		writeError(w, http.StatusNotFound, "no such endpoint")
		return
	}

	if _, err := fs.Stat(staticFS, path); err != nil {
		// Unknown path: let the SPA router handle it.
		path = "index.html"
	}

	w.Header().Set("Cache-Control", "no-cache")

	data, err := fs.ReadFile(staticFS, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(path, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(path, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	_, _ = w.Write(data)
}

func clientIP(r *http.Request) string {
	if host, _, err := splitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

func splitHostPort(addr string) (string, string, error) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return "", "", errors.New("missing port")
	}

	return strings.Trim(addr[:idx], "[]"), addr[idx+1:], nil
}

// drainBody consumes and closes a request body.
func drainBody(r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
}
