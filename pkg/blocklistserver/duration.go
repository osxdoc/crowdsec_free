package blocklistserver

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses the durations accepted in decisions: Go durations
// ("4h30m") plus the day and week suffixes used by cscli ("30d", "1w").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}

	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("duration must be positive: %q", s)
		}

		return d, nil
	}

	unit := s[len(s)-1]
	number := s[:len(s)-1]

	var multiplier time.Duration

	switch unit {
	case 'd':
		multiplier = 24 * time.Hour
	case 'w':
		multiplier = 7 * 24 * time.Hour
	default:
		return 0, fmt.Errorf("invalid duration %q", s)
	}

	n, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}

	if n <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}

	return time.Duration(n * float64(multiplier)), nil
}
