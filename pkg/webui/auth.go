package webui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "cswebui_session"
	// wrongPasswordHash is a valid bcrypt hash used to keep the timing of
	// "unknown user" and "wrong password" comparable.
	wrongPasswordHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	maxLoginFailures  = 10
	failureWindow     = 5 * time.Minute
)

type sessionManager struct {
	secret []byte
	ttl    time.Duration
	secure bool
	users  map[string]string

	now func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time
}

type sessionPayload struct {
	User   string `json:"u"`
	Expire int64  `json:"e"`
}

func newSessionManager(cfg *Config) (*sessionManager, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating session secret: %w", err)
	}

	users := make(map[string]string, len(cfg.Auth.Users))

	for _, user := range cfg.Auth.Users {
		if _, exists := users[user.Username]; exists {
			return nil, fmt.Errorf("duplicate user %q", user.Username)
		}

		users[user.Username] = user.PasswordHash
	}

	return &sessionManager{
		secret:   secret,
		ttl:      cfg.SessionTTLDuration(),
		secure:   cfg.Auth.SecureCookie,
		users:    users,
		now:      time.Now,
		failures: map[string][]time.Time{},
	}, nil
}

// login verifies credentials and returns a signed session cookie value plus
// the matching CSRF token.
func (s *sessionManager) login(username, password, ip string) (string, string, error) {
	if s.tooManyFailures(ip) {
		return "", "", errors.New("too many failed logins, try again later")
	}

	hash, ok := s.users[username]
	if !ok {
		// Still run bcrypt so a missing user is not faster than a bad password.
		_ = bcrypt.CompareHashAndPassword([]byte(wrongPasswordHash), []byte(password))
		s.recordFailure(ip)

		return "", "", errors.New("invalid username or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		s.recordFailure(ip)

		return "", "", errors.New("invalid username or password")
	}

	token, err := s.token(username)
	if err != nil {
		return "", "", err
	}

	return token, s.csrf(token), nil
}

func (s *sessionManager) token(username string) (string, error) {
	payload, err := json.Marshal(sessionPayload{User: username, Expire: s.now().Add(s.ttl).Unix()})
	if err != nil {
		return "", fmt.Errorf("encoding session: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))

	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verify validates the session cookie and returns the user and CSRF token.
func (s *sessionManager) verify(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", "", false
	}

	value := cookie.Value

	encoded, sig, ok := strings.Cut(value, ".")
	if !ok {
		return "", "", false
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))

	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
		return "", "", false
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	var payload sessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", false
	}

	if s.now().Unix() >= payload.Expire {
		return "", "", false
	}

	if _, ok := s.users[payload.User]; !ok {
		return "", "", false
	}

	return payload.User, s.csrf(value), true
}

// csrf derives the CSRF token from the session value: changing the session
// invalidates both, and no server-side state is needed.
func (s *sessionManager) csrf(sessionToken string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte("csrf:" + sessionToken))

	return hex.EncodeToString(mac.Sum(nil))
}

func (s *sessionManager) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.ttl.Seconds()),
	})
}

func (s *sessionManager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (s *sessionManager) tooManyFailures(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := s.now().Add(-failureWindow)
	attempts := s.failures[ip]

	recent := attempts[:0]

	for _, attempt := range attempts {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}

	s.failures[ip] = recent

	return len(recent) >= maxLoginFailures
}

func (s *sessionManager) recordFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failures[ip] = append(s.failures[ip], s.now())
}
