package blocklistserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const maxBodySize = 8 << 20 // 8 MiB

var machineIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}$`)

// Server exposes the CAPI-compatible API and the admin API used by cswebui.
type Server struct {
	cfg    *Config
	store  *Store
	signer *TokenSigner
	log    *logrus.Logger
	now    func() time.Time
}

// NewServer validates cfg and builds a server around store.
func NewServer(cfg *Config, store *Store, log *logrus.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}

	if store == nil {
		return nil, errors.New("nil store")
	}

	if err := cfg.SetDefaults(); err != nil {
		return nil, err
	}

	signer, err := NewTokenSigner(cfg.TokenTTLDuration())
	if err != nil {
		return nil, err
	}

	if log == nil {
		log = logrus.New()
	}

	return &Server{cfg: cfg, store: store, signer: signer, log: log, now: time.Now}, nil
}

// Handler returns the HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /", s.handleHealth)

	// Engines speak CAPI v3; v1 is kept for older releases and for testing.
	for _, prefix := range []string{"v1", "v3"} {
		base := "/" + prefix

		mux.HandleFunc("POST "+base+"/watchers", s.handleRegister)
		mux.HandleFunc("POST "+base+"/watchers/login", s.handleLogin)
		mux.HandleFunc("DELETE "+base+"/watchers/self", s.withMachine(s.handleUnregister))

		mux.HandleFunc("GET "+base+"/decisions/stream", s.withMachine(s.handleStream))
		mux.HandleFunc("POST "+base+"/signals", s.withMachine(s.handlePushSignals))
		mux.HandleFunc("POST "+base+"/alerts", s.withMachine(s.handlePushAlerts))
		mux.HandleFunc("GET "+base+"/allowlists", s.withMachine(s.handleAllowlists))

		mux.HandleFunc("POST "+base+"/usage-metrics", s.withMachine(s.handleNoop))
		mux.HandleFunc("POST "+base+"/metrics/", s.withMachine(s.handleNoop))
		mux.HandleFunc("POST "+base+"/heartbeat", s.withMachine(s.handleNoop))

		// Console enrollment is a cloud feature; answer clearly instead of 404.
		mux.HandleFunc("POST "+base+"/watchers/enroll", func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusNotImplemented,
				"console enrollment is not supported: this engine is managed by a self-hosted blocklist server")
		})
	}

	mux.HandleFunc("GET /admin/v1/stats", s.withAdmin(s.handleAdminStats))
	mux.HandleFunc("GET /admin/v1/decisions", s.withAdmin(s.handleAdminListDecisions))
	mux.HandleFunc("POST /admin/v1/decisions", s.withAdmin(s.handleAdminCreateDecision))
	mux.HandleFunc("DELETE /admin/v1/decisions/{id}", s.withAdmin(s.handleAdminDeleteDecision))
	mux.HandleFunc("GET /admin/v1/machines", s.withAdmin(s.handleAdminListMachines))
	mux.HandleFunc("DELETE /admin/v1/machines/{id}", s.withAdmin(s.handleAdminDeleteMachine))

	return s.logRequests(mux)
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

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}

	return nil
}

type ctxKey string

const ctxMachineKey ctxKey = "machine"

func machineFromContext(ctx context.Context) string {
	machineID, _ := ctx.Value(ctxMachineKey).(string)
	return machineID
}

func (s *Server) withMachine(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		machineID, err := s.signer.Verify(token, s.now())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "%s", err)
			return
		}

		if _, err := s.store.Machine(r.Context(), machineID); err != nil {
			writeError(w, http.StatusUnauthorized, "unknown machine %q", machineID)
			return
		}

		_ = s.store.TouchMachine(r.Context(), machineID, clientIP(r))

		next(w, r.WithContext(context.WithValue(r.Context(), ctxMachineKey, machineID)))
	}
}

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminAllowed(r) {
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}

		next(w, r)
	}
}

func (s *Server) adminAllowed(r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		// No token configured: only loopback may manage the blocklist.
		return isLoopback(r)
	}

	token := bearerToken(r)
	if token == "" {
		token = r.Header.Get("X-Admin-Token")
	}

	return SecureCompare(token, s.cfg.AdminToken)
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}

	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}

	return strings.TrimSpace(token)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func isLoopback(r *http.Request) bool {
	ip, err := netip.ParseAddr(clientIP(r))
	return err == nil && ip.IsLoopback()
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "csblocklistd",
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req models.WatcherRegistrationRequest

	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if req.MachineID == nil || req.Password == nil {
		writeError(w, http.StatusBadRequest, "machine_id and password are required")
		return
	}

	if !machineIDPattern.MatchString(*req.MachineID) {
		writeError(w, http.StatusBadRequest, "invalid machine_id, expected [a-zA-Z0-9_.@-]{1,64}")
		return
	}

	if len(*req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	if s.cfg.RegistrationToken != "" {
		token := req.RegistrationToken
		if token == "" {
			token = r.Header.Get("X-Registration-Token")
		}

		if !SecureCompare(token, s.cfg.RegistrationToken) {
			writeError(w, http.StatusUnauthorized, "invalid registration token")
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.log.Errorf("hashing password: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.store.RegisterMachine(r.Context(), *req.MachineID, string(hash), clientIP(r)); err != nil {
		if strings.Contains(err.Error(), "already registered") {
			writeError(w, http.StatusConflict, "%s", err)
			return
		}

		s.log.Errorf("registering machine: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.log.Infof("registered machine %q from %s", *req.MachineID, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]string{"message": "machine registered"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req models.WatcherAuthRequest

	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if req.MachineID == nil || req.Password == nil {
		writeError(w, http.StatusBadRequest, "machine_id and password are required")
		return
	}

	machine, err := s.store.Machine(r.Context(), *req.MachineID)
	if err != nil {
		// Compare against a dummy hash so a missing machine and a bad password
		// take the same time.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"), []byte(*req.Password))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(machine.PasswordHash), []byte(*req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	_ = s.store.TouchMachine(r.Context(), machine.MachineID, clientIP(r))

	token, expire := s.signer.Sign(machine.MachineID, s.now())

	writeJSON(w, http.StatusOK, models.WatcherAuthResponse{
		Code:   http.StatusOK,
		Token:  token,
		Expire: expire.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	machineID := machineFromContext(r.Context())

	if err := s.store.DeleteMachine(r.Context(), machineID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.log.Infof("unregistered machine %q", machineID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "machine unregistered"})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	machineID := machineFromContext(ctx)

	startup := r.URL.Query().Get("startup") == "true"

	if _, err := s.store.ExpireDecisions(ctx); err != nil {
		s.log.Errorf("expiring decisions: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	revision, err := s.store.CurrentRevision(ctx)
	if err != nil {
		s.log.Errorf("reading revision: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var (
		decisions  []*Decision
		tombstones []*Tombstone
	)

	cursor, err := s.store.Cursor(ctx, machineID)
	if err != nil {
		s.log.Errorf("reading cursor: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if startup {
		decisions, err = s.store.ActiveDecisions(ctx)
	} else {
		decisions, err = s.store.DecisionsAfter(ctx, cursor)
	}

	if err != nil {
		s.log.Errorf("loading decisions: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !startup {
		tombstones, err = s.store.TombstonesAfter(ctx, cursor)
		if err != nil {
			s.log.Errorf("loading deletions: %s", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	if err := s.store.SetCursor(ctx, machineID, revision); err != nil {
		s.log.Errorf("writing cursor: %s", err)
	}

	response := buildStreamResponse(decisions, tombstones, s.cfg.CommunityScenario)

	s.log.Infof("serving %d decisions (%d deleted) to %q (startup=%t)",
		len(decisions), len(tombstones), machineID, startup)

	writeJSON(w, http.StatusOK, response)
}

// buildStreamResponse groups decisions the way CAPI does: one entry per
// scenario and scope, with the values in a nested list.
func buildStreamResponse(decisions []*Decision, tombstones []*Tombstone, scenario string) *modelscapi.GetDecisionsStreamResponse {
	type groupKey struct {
		scenario string
		scope    string
	}

	groups := map[groupKey]*modelscapi.GetDecisionsStreamResponseNewItem{}
	order := make([]groupKey, 0)

	for _, d := range decisions {
		// Engines only apply ban decisions from the stream; sending others
		// would silently turn them into bans.
		if d.Type != "ban" && d.Type != "" {
			continue
		}

		key := groupKey{scenario: scenario, scope: d.Scope}

		group, ok := groups[key]
		if !ok {
			group = &modelscapi.GetDecisionsStreamResponseNewItem{
				Scenario:  new(scenario),
				Scope:     new(d.Scope),
				Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{},
			}
			groups[key] = group
			order = append(order, key)
		}

		group.Decisions = append(group.Decisions, &modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
			Value:    new(d.Value),
			Duration: new(d.Duration),
		})
	}

	response := &modelscapi.GetDecisionsStreamResponse{
		New:     modelscapi.GetDecisionsStreamResponseNew{},
		Deleted: modelscapi.GetDecisionsStreamResponseDeleted{},
	}

	for _, key := range order {
		response.New = append(response.New, groups[key])
	}

	deletedGroups := map[string]*modelscapi.GetDecisionsStreamResponseDeletedItem{}
	deletedOrder := make([]string, 0)

	for _, t := range tombstones {
		group, ok := deletedGroups[t.Scope]
		if !ok {
			group = &modelscapi.GetDecisionsStreamResponseDeletedItem{
				Scope:     new(t.Scope),
				Decisions: []string{},
			}
			deletedGroups[t.Scope] = group
			deletedOrder = append(deletedOrder, t.Scope)
		}

		group.Decisions = append(group.Decisions, t.Value)
	}

	for _, scope := range deletedOrder {
		response.Deleted = append(response.Deleted, deletedGroups[scope])
	}

	return response
}

func (s *Server) handlePushAlerts(w http.ResponseWriter, r *http.Request) {
	machineID := machineFromContext(r.Context())

	var alerts models.AddAlertsRequest

	if err := s.decodeJSON(w, r, &alerts); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if len(alerts) > s.cfg.Push.MaxAlertsPerRequest {
		writeError(w, http.StatusRequestEntityTooLarge, "too many alerts, limit is %d", s.cfg.Push.MaxAlertsPerRequest)
		return
	}

	accepted := 0

	for _, alert := range alerts {
		if alert == nil {
			continue
		}

		scenario := ""
		if alert.Scenario != nil {
			scenario = *alert.Scenario
		}

		for i, decision := range alert.Decisions {
			if i >= s.cfg.Push.MaxDecisionsPerAlert {
				break
			}

			if decision == nil {
				continue
			}

			if err := s.ingestDecision(r.Context(), machineID, scenario, decision); err != nil {
				s.log.Debugf("skipping pushed decision: %s", err)
				continue
			}

			accepted++
		}
	}

	s.log.Infof("machine %q pushed %d alerts, %d decisions accepted", machineID, len(alerts), accepted)

	writeJSON(w, http.StatusCreated, map[string]any{"message": "alerts received", "decisions": accepted})
}

// handlePushSignals ingests the signal payload used by CAPI v3, which the
// engine posts every push interval.
func (s *Server) handlePushSignals(w http.ResponseWriter, r *http.Request) {
	machineID := machineFromContext(r.Context())

	var signals modelscapi.AddSignalsRequest

	if err := s.decodeJSON(w, r, &signals); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if len(signals) > s.cfg.Push.MaxAlertsPerRequest {
		writeError(w, http.StatusRequestEntityTooLarge, "too many signals, limit is %d", s.cfg.Push.MaxAlertsPerRequest)
		return
	}

	accepted := 0

	for _, signal := range signals {
		if signal == nil {
			continue
		}

		signalScenario := derefString(signal.Scenario)

		for i, decision := range signal.Decisions {
			if i >= s.cfg.Push.MaxDecisionsPerAlert {
				break
			}

			if decision == nil || decision.Simulated {
				continue
			}

			if decision.Type != nil && *decision.Type != "ban" {
				continue
			}

			origin := derefString(decision.Origin)
			if origin == "" {
				origin = "cscli"
			}

			scenario := derefString(decision.Scenario)
			if scenario == "" {
				scenario = signalScenario
			}

			if err := s.ingest(r.Context(), machineID, origin, scenario,
				derefString(decision.Scope), derefString(decision.Value), derefString(decision.Duration)); err != nil {
				s.log.Debugf("skipping pushed signal decision: %s", err)
				continue
			}

			accepted++
		}
	}

	s.log.Infof("machine %q pushed %d signals, %d decisions accepted", machineID, len(signals), accepted)

	// The engine only logs a warning unless the answer is a plain 200.
	writeJSON(w, http.StatusOK, map[string]any{"message": "signals received", "decisions": accepted})
}

func (s *Server) ingestDecision(ctx context.Context, machineID, scenario string, decision *models.Decision) error {
	if decision.Value == nil || decision.Scope == nil {
		return errors.New("decision without value or scope")
	}

	origin := derefString(decision.Origin)
	if origin == "" {
		origin = "cscli"
	}

	return s.ingest(ctx, machineID, origin, scenario,
		*decision.Scope, *decision.Value, derefString(decision.Duration))
}

func (s *Server) ingest(ctx context.Context, machineID, origin, scenario, scope, value, duration string) error {
	if !s.cfg.AcceptsOrigin(origin) {
		return fmt.Errorf("origin %q is not shared", origin)
	}

	normalizedScope, normalizedValue, err := normalizeScopeValue(scope, value)
	if err != nil {
		return err
	}

	until, canonicalDuration, err := s.expiry(duration)
	if err != nil {
		return err
	}

	if scenario == "" {
		scenario = "manual"
	}

	dec := &Decision{
		Value:     normalizedValue,
		Scope:     normalizedScope,
		Type:      "ban",
		Duration:  canonicalDuration,
		Scenario:  scenario,
		Origin:    origin,
		Source:    "push",
		MachineID: machineID,
		Until:     until,
	}

	return s.store.UpsertDecision(ctx, dec)
}

// expiry validates a duration and returns the absolute expiry (nil for
// permanent decisions) plus the duration string in canonical form.
func (s *Server) expiry(duration string) (*time.Time, string, error) {
	if strings.TrimSpace(duration) == "0" || duration == "" {
		return nil, "0s", nil
	}

	parsed, err := ParseDuration(duration)
	if err != nil {
		return nil, "", err
	}

	if parsed > 30*24*time.Hour {
		return nil, "", fmt.Errorf("duration %q is longer than 30d", duration)
	}

	until := s.now().UTC().Add(parsed)

	// Engines parse durations with time.ParseDuration, which does not know
	// "d" or "w": always serve the canonical form.
	return &until, parsed.String(), nil
}

func normalizeScopeValue(scope, value string) (string, string, error) {
	value = strings.TrimSpace(value)

	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "ip":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return "", "", fmt.Errorf("invalid ip %q: %w", value, err)
		}

		return "Ip", addr.String(), nil
	case "range":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", "", fmt.Errorf("invalid range %q: %w", value, err)
		}

		return "Range", prefix.Masked().String(), nil
	default:
		return "", "", fmt.Errorf("unsupported scope %q, only ip and range are shared", scope)
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

func (s *Server) handleAllowlists(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, models.GetAllowlistsResponse{})
}

func (s *Server) handleNoop(w http.ResponseWriter, r *http.Request) {
	_, _ = w, r
	writeJSON(w, http.StatusOK, map[string]string{"message": "ok"})
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		s.log.Errorf("computing stats: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleAdminListDecisions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil || limit <= 0 || limit > 5000 {
		limit = 500
	}

	offset, err := strconv.Atoi(query.Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}

	filter := DecisionFilter{
		Scenario:       strings.TrimSpace(query.Get("scenario")),
		Value:          strings.TrimSpace(query.Get("value")),
		IncludeDeleted: query.Get("include_deleted") == "true",
		Limit:          limit,
		Offset:         offset,
	}

	decisions, err := s.store.ListDecisions(r.Context(), filter)
	if err != nil {
		s.log.Errorf("listing decisions: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"decisions": decisions})
}

type adminDecisionRequest struct {
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

func (s *Server) handleAdminCreateDecision(w http.ResponseWriter, r *http.Request) {
	var req adminDecisionRequest

	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if req.Scope == "" {
		req.Scope = "ip"
	}

	scope, value, err := normalizeScopeValue(req.Scope, req.Value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	until, duration, err := s.expiry(req.Duration)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if req.Type == "" {
		req.Type = "ban"
	}

	if req.Scenario == "" {
		req.Scenario = "manual"
	}

	decision := &Decision{
		Value:    value,
		Scope:    scope,
		Type:     req.Type,
		Duration: duration,
		Scenario: req.Scenario,
		Origin:   "cscli",
		Source:   "manual",
		Until:    until,
	}

	if err := s.store.UpsertDecision(r.Context(), decision); err != nil {
		s.log.Errorf("creating decision: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.log.Infof("admin added %s %s (%s)", scope, value, duration)

	writeJSON(w, http.StatusCreated, decision)
}

func (s *Server) handleAdminDeleteDecision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid decision id")
		return
	}

	if err := s.store.DeleteDecision(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "decision not found")
			return
		}

		s.log.Errorf("deleting decision: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "decision deleted"})
}

func (s *Server) handleAdminListMachines(w http.ResponseWriter, r *http.Request) {
	machines, err := s.store.ListMachines(r.Context())
	if err != nil {
		s.log.Errorf("listing machines: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Never expose password hashes.
	type machineView struct {
		MachineID string    `json:"machine_id"`
		CreatedAt time.Time `json:"created_at"`
		LastSeen  time.Time `json:"last_seen"`
		LastIP    string    `json:"last_ip"`
	}

	views := make([]machineView, 0, len(machines))

	for _, m := range machines {
		views = append(views, machineView{MachineID: m.MachineID, CreatedAt: m.CreatedAt, LastSeen: m.LastSeen, LastIP: m.LastIP})
	}

	writeJSON(w, http.StatusOK, map[string]any{"machines": views})
}

func (s *Server) handleAdminDeleteMachine(w http.ResponseWriter, r *http.Request) {
	machineID := r.PathValue("id")
	if machineID == "" {
		writeError(w, http.StatusBadRequest, "invalid machine id")
		return
	}

	if err := s.store.DeleteMachine(r.Context(), machineID); err != nil {
		s.log.Errorf("deleting machine: %s", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "machine deleted"})
}
