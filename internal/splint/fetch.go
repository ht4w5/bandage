package splint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Fetcher retrieves the report document from a bandage API over HTTP or
// HTTPS: the server is verified against a CA, and an optional client
// certificate and key are presented to it (mutual TLS) — bandaid's
// fetch surface. There is no insecure mode: an unverified server is
// refused, never accepted.
type Fetcher struct {
	url      string
	client   *http.Client
	maxBytes int64
}

// Fetch defaults mirror bandaid's: a 10s timeout and a 32 MiB cap on
// the accepted document size.
const (
	// DefaultFetchTimeout is the fetch timeout unless the operator says
	// otherwise (bandaid's default).
	DefaultFetchTimeout = 10 * time.Second
	maxReportBytes      = 32 << 20
)

// Option configures a Fetcher at construction.
type Option func(*fetchOpts)

type fetchOpts struct {
	caFile   string
	certFile string
	keyFile  string
	timeout  time.Duration
}

// WithTLS loads the operator's PKI material — bandaid's --cacert,
// --cert and --key one to one. caFile is the CA that verifies the
// server (empty keeps the system roots); certFile and keyFile are the
// client certificate and key presented to it, and must be provided
// together.
func WithTLS(caFile, certFile, keyFile string) Option {
	return func(o *fetchOpts) {
		o.caFile, o.certFile, o.keyFile = caFile, certFile, keyFile
	}
}

// WithFetchTimeout sets the fetch timeout (bandaid's --fetch-timeout).
func WithFetchTimeout(timeout time.Duration) Option {
	return func(o *fetchOpts) { o.timeout = timeout }
}

// NewFetcher builds a Fetcher for the report document at rawURL, which
// must be an http or https URL with a host; opts may load the
// operator's PKI material and set the fetch timeout.
func NewFetcher(rawURL string, opts ...Option) (*Fetcher, error) {
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
	o := fetchOpts{timeout: DefaultFetchTimeout}
	for _, opt := range opts {
		opt(&o)
	}
	if o.timeout < time.Second {
		return nil, fmt.Errorf("fetch timeout: must not be shorter than 1 second (got %s)", o.timeout)
	}
	client, err := newMTLSClient(o.caFile, o.certFile, o.keyFile, o.timeout)
	if err != nil {
		return nil, err
	}
	return &Fetcher{
		url:      rawURL,
		client:   client,
		maxBytes: maxReportBytes,
	}, nil
}

// newMTLSClient is bandaid's HTTP-client construction: a client that
// verifies the server against caFile and, when certFile and keyFile are
// provided together, presents them to it. TLS 1.2 is the floor and
// InsecureSkipVerify is never set.
func newMTLSClient(caFile, certFile, keyFile string, timeout time.Duration) (*http.Client, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("client cert and key must be provided together: cert=%q key=%q", certFile, keyFile)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("bad CA pem: %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert %q/%q: %w", certFile, keyFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = tlsCfg

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
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
