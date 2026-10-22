package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// blocklistClient talks to the admin API of a csblocklistd instance.
type blocklistClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newBlocklistClient(cfg *BlocklistConfig) *blocklistClient {
	return &blocklistClient{
		baseURL: strings.TrimSuffix(cfg.AdminURL, "/"),
		token:   cfg.AdminToken,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *blocklistClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}

		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("calling blocklist server: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		var errResp errorResponse
		if err := json.Unmarshal(payload, &errResp); err == nil && errResp.Message != "" {
			return errors.New(errResp.Message)
		}

		return fmt.Errorf("blocklist server returned %s", resp.Status)
	}

	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
