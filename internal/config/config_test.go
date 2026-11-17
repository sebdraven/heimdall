package config

import (
	"strings"
	"testing"
	"time"
)

func TestLookylooTimeouts(t *testing.T) {
	for _, tt := range []struct {
		desc, timeout, request   string
		wantTimeout, wantRequest time.Duration
		wantErr                  string
	}{
		{desc: "defaults", wantTimeout: 100 * time.Second, wantRequest: 45 * time.Second},
		{desc: "set", timeout: "110s", request: "30s", wantTimeout: 110 * time.Second, wantRequest: 30 * time.Second},
		{desc: "equal", timeout: "45s", request: "45s", wantTimeout: 45 * time.Second, wantRequest: 45 * time.Second},
		{desc: "timeout not a duration", timeout: "soon", wantErr: "HEIMDALL_LOOKYLOO_TIMEOUT: time: invalid duration"},
		{desc: "request timeout without unit", request: "45", wantErr: "HEIMDALL_LOOKYLOO_REQUEST_TIMEOUT: time: missing unit"},
		{desc: "timeout zero", timeout: "0s", wantErr: "HEIMDALL_LOOKYLOO_TIMEOUT: must be positive"},
		{desc: "request timeout negative", request: "-1s", wantErr: "HEIMDALL_LOOKYLOO_REQUEST_TIMEOUT: must be positive"},
		{desc: "timeout below the request timeout", timeout: "30s", request: "45s", wantErr: "HEIMDALL_LOOKYLOO_TIMEOUT: must be at least HEIMDALL_LOOKYLOO_REQUEST_TIMEOUT (45s)"},
		{desc: "timeout of the job", timeout: "2m", wantErr: "HEIMDALL_LOOKYLOO_TIMEOUT: must be below the 2m0s of the enrichment job"},
		{desc: "timeout past the job", timeout: "5m", wantErr: "HEIMDALL_LOOKYLOO_TIMEOUT: must be below the 2m0s of the enrichment job"},
	} {
		t.Setenv(prefix+"PG_DSN", "postgres://heimdall@localhost/heimdall")
		t.Setenv(prefix+"LOOKYLOO_TIMEOUT", tt.timeout)
		t.Setenv(prefix+"LOOKYLOO_REQUEST_TIMEOUT", tt.request)
		c, err := Load()
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tt.desc, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tt.desc, err)
			continue
		}
		if c.LookylooTimeout != tt.wantTimeout || c.LookylooRequestTimeout != tt.wantRequest {
			t.Errorf("%s: timeout %s, request timeout %s, want %s and %s", tt.desc, c.LookylooTimeout, c.LookylooRequestTimeout, tt.wantTimeout, tt.wantRequest)
		}
	}
}
