package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const userAgent = "heimdall"

// getJSON decodes into v the answer to a GET of url, read up to limit bytes.
func getJSON(ctx context.Context, hc *http.Client, url, accept string, limit int64, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, limit)).Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
