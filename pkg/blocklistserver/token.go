package blocklistserver

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
	"strings"
	"time"
)

// TokenSigner issues and verifies the opaque bearer tokens handed out at
// /v1/watchers/login. Engines treat them as opaque JWTs, so a compact
// HMAC-signed payload is enough.
type TokenSigner struct {
	secret []byte
	ttl    time.Duration
}

type tokenPayload struct {
	MachineID string `json:"m"`
	Expire    int64  `json:"e"`
}

// NewTokenSigner creates a signer with a random in-memory secret. Tokens do
// not survive a restart; engines simply log in again on the next 401.
func NewTokenSigner(ttl time.Duration) (*TokenSigner, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("token ttl must be positive, got %s", ttl)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating token secret: %w", err)
	}

	return &TokenSigner{secret: secret, ttl: ttl}, nil
}

// Sign returns a token for machineID and its expiry.
func (s *TokenSigner) Sign(machineID string, now time.Time) (string, time.Time) {
	expire := now.Add(s.ttl)

	payload, _ := json.Marshal(tokenPayload{MachineID: machineID, Expire: expire.Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))

	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return encoded + "." + sig, expire
}

// Verify checks a token and returns the machine id it was issued for.
func (s *TokenSigner) Verify(token string, now time.Time) (string, error) {
	encoded, sig, ok := strings.Cut(token, ".")
	if !ok {
		return "", errors.New("malformed token")
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))

	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
		return "", errors.New("invalid token signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("malformed token payload")
	}

	var payload tokenPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", errors.New("malformed token payload")
	}

	if now.Unix() >= payload.Expire {
		return "", errors.New("token expired")
	}

	if payload.MachineID == "" {
		return "", errors.New("token has no machine id")
	}

	return payload.MachineID, nil
}

// SecureCompare compares two secrets without leaking timing information.
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateToken returns a random token suitable for admin_token or
// registration_token.
func GenerateToken() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}

	return hex.EncodeToString(buf), nil
}
