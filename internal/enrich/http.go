package enrich

import (
	"bytes"
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
	return decodeAnswer(hc, req, accept, limit, v)
}

// postJSON decodes into v the answer to a POST of body, as JSON, to url.
func postJSON(ctx context.Context, hc *http.Client, url string, body any, limit int64, v any) error {
	req, err := jsonRequest(ctx, url, body)
	if err != nil {
		return err
	}
	return decodeAnswer(hc, req, "application/json", limit, v)
}

// postRaw returns the answer to a POST of body, as JSON, to url, read up to
// limit bytes.
func postRaw(ctx context.Context, hc *http.Client, url string, body any, limit int64) ([]byte, error) {
	req, err := jsonRequest(ctx, url, body)
	if err != nil {
		return nil, err
	}
	res, err := send(hc, req, "application/json")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(io.LimitReader(res.Body, limit))
}

func jsonRequest(ctx context.Context, url string, body any) (*http.Request, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func decodeAnswer(hc *http.Client, req *http.Request, accept string, limit int64, v any) error {
	res, err := send(hc, req, accept)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := json.NewDecoder(io.LimitReader(res.Body, limit)).Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// send returns the answer to req, or a statusError unless 200.
func send(hc *http.Client, req *http.Request, accept string) (*http.Response, error) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(res.Body, maxErrBody))
		return nil, &statusError{Code: res.StatusCode, RetryAfter: res.Header.Get("Retry-After"), Body: string(body)}
	}
	return res, nil
}
