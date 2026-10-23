package splint

import (
	"strings"
	"testing"
	"time"
)

// Primary seam: the fetcher's construction — the operator's fetch
// options validated at the module that owns them (bandaid's fetch
// surface): the report URL, the fetch timeout and the client
// certificate pair. One failing and one passing case per validation.

// TestNewFetcherValidatesTheClientCertificatePair: the client
// certificate and key are provided together or not at all — a
// certificate without its key (or a key without its certificate) is
// refused at construction, and the pair is accepted together.
func TestNewFetcherValidatesTheClientCertificatePair(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		wantErr  string
	}{
		{
			name:     "a client certificate without its key is refused",
			certFile: pki.certFile,
			keyFile:  "",
			wantErr:  "client cert and key must be provided together",
		},
		{
			name:     "a client key without its certificate is refused",
			certFile: "",
			keyFile:  pki.keyFile,
			wantErr:  "client cert and key must be provided together",
		},
		{
			name:     "a client certificate with its key is accepted",
			certFile: pki.certFile,
			keyFile:  pki.keyFile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFetcher("http://example.com/report", WithTLS(pki.caFile, tt.certFile, tt.keyFile))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("NewFetcher accepted cert=%q key=%q, want error containing %q", tt.certFile, tt.keyFile, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("NewFetcher error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewFetcher: %v", err)
			}
			if f == nil {
				t.Fatal("NewFetcher = nil fetcher")
			}
		})
	}
}

// TestNewFetcherValidatesTheFetchTimeout: the fetch timeout —
// bandaid's 10s default, configurable, with a one-second floor — a
// failing and a passing case per validation.
func TestNewFetcherValidatesTheFetchTimeout(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		want    time.Duration
		wantErr string
	}{
		{
			name: "the fetch timeout defaults to bandaid's ten seconds",
			want: 10 * time.Second,
		},
		{
			name: "the fetch timeout is configurable",
			opts: []Option{WithFetchTimeout(2 * time.Second)},
			want: 2 * time.Second,
		},
		{
			name:    "a fetch timeout below the one-second floor is refused",
			opts:    []Option{WithFetchTimeout(500 * time.Millisecond)},
			wantErr: "fetch timeout: must not be shorter than 1 second",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFetcher("http://example.com/report", tt.opts...)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("NewFetcher accepted a below-floor fetch timeout, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("NewFetcher error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewFetcher: %v", err)
			}
			if f.client.Timeout != tt.want {
				t.Errorf("fetch timeout = %v, want %v", f.client.Timeout, tt.want)
			}
		})
	}
}

// TestNewFetcherValidatesTheReportURL: the report URL — required, an
// http or https URL with a host — a failing and a passing case per
// validation.
func TestNewFetcherValidatesTheReportURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "an empty report URL is refused",
			url:     "",
			wantErr: "url: required",
		},
		{
			name:    "a non-http(s) report URL is refused",
			url:     "ftp://example.com/report",
			wantErr: "url: scheme must be http or https",
		},
		{
			name:    "a report URL without a host is refused",
			url:     "http:///report",
			wantErr: "url: host: required",
		},
		{
			name: "an http report URL with a host is accepted",
			url:  "http://example.com/report",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFetcher(tt.url)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("NewFetcher(%q) accepted, want error containing %q", tt.url, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("NewFetcher(%q) error %q does not contain %q", tt.url, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewFetcher(%q): %v", tt.url, err)
			}
			if f == nil {
				t.Fatalf("NewFetcher(%q) = nil fetcher", tt.url)
			}
		})
	}
}
