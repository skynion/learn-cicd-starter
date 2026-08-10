package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantKey    string
		wantErr    bool
		missingErr bool
	}{
		{
			name:    "valid API key",
			header:  "ApiKey secret-token",
			wantKey: "secret-token",
		},
		{
			name:       "missing authorization header",
			wantErr:    true,
			missingErr: true,
		},
		{
			name:    "malformed authorization header",
			header:  "Bearer secret-token",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			key, err := GetAPIKey(headers)
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.missingErr && !errors.Is(err, ErrNoAuthHeaderIncluded) {
				t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
			}
			if key != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, key)
			}
		})
	}
}
