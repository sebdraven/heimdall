package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	userAgent  = "heimdall"
	maxErrBody = 4 << 10
)

// statusError is an answer other than 200; Body is its start.
type statusError struct {
	Code       int
	RetryAfter string
	Body       string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

// getJSON decodes into v the answer to a GET of url, read up to limit bytes.
func getJSON(ctx context.Context, hc *http.Client, url, accept string, limit int64, v any) error {
	return fetchJSON(ctx, hc, url, accept, nil, limit, v)
}

// fetchJSON is getJSON with the request headers of header.
func fetchJSON(ctx context.Context, hc *http.Client, url, accept string, header http.Header, limit int64, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, maxErrBody))
		return &statusError{Code: res.StatusCode, RetryAfter: res.Header.Get("Retry-After"), Body: string(body)}
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, limit)).Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
