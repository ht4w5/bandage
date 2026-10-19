package splint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Fetcher retrieves the report document from a bandage API over plain
// HTTP(S) — bandage itself serves plain HTTP. Ticket 08 adds mutual TLS
// and the fetch-timeout flag on top of this surface.
type Fetcher struct {
	url      string
	client   *http.Client
	maxBytes int64
}

// Fetch defaults mirror bandaid's: a 10s timeout and a 32 MiB cap on
// the accepted document size.
const (
	defaultFetchTimeout = 10 * time.Second
	maxReportBytes      = 32 << 20
)

// NewFetcher builds a Fetcher for the report document at rawURL, which
// must be an http or https URL with a host.
func NewFetcher(rawURL string) (*Fetcher, error) {
	if rawURL == "" {
		return nil, errors.New("url: required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url: parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("url: scheme must be http or https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("url: host: required")
	}
	return &Fetcher{
		url:      rawURL,
		client:   &http.Client{Timeout: defaultFetchTimeout},
		maxBytes: maxReportBytes,
	}, nil
}

// Fetch retrieves the report document's bytes: a 200 response within
// the size cap, or an error the caller treats as a failed cycle.
func (f *Fetcher) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: bad http response: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch: read report document: %w", err)
	}
	if int64(len(data)) > f.maxBytes {
		return nil, fmt.Errorf("fetch: report document too large (over %d bytes)", f.maxBytes)
	}
	return data, nil
}
