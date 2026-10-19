package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Primary seam: run's command line and startup validation — what the
// operator can pass and what the program refuses before any network
// I/O or firewall work. Every validation gets a failing and a passing
// case.

// writeSelfSigned writes a throwaway self-signed certificate and key as
// PEM files — the shape the operator's PKI runbook leaves on disk — and
// returns their paths. The self-signed certificate doubles as the CA
// file (--cacert): it is a well-formed certificate PEM either way.
// (Deliberately small and local: internal/splint's transport tests mint
// their own PKI, like shippedformat_test.go pins its own fixtures.)
func writeSelfSigned(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "splint-nft startup test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certFile = filepath.Join(t.TempDir(), "client.crt")
	keyFile = filepath.Join(t.TempDir(), "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// newPlainDocServer is the plain-HTTP report endpoint: one empty
// version-0 document, enough to complete a --dry-run startup.
func newPlainDocServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"version":0,"generated_at":"2025-10-17T18:00:00Z","reports":[]}`) // error ignored: tests assert the outcome
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRunValidatesTheClientCertificatePair: startup validation — a
// client certificate without its key (or a key without its
// certificate) is rejected before any network I/O, and the pair is
// accepted together.
func TestRunValidatesTheClientCertificatePair(t *testing.T) {
	certFile, keyFile := writeSelfSigned(t)

	t.Run("a client certificate without its key is rejected at startup", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--cert", certFile}, io.Discard, &stderr)
		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "client cert and key must be provided together") {
			t.Errorf("stderr %q does not reject the unpaired client certificate", stderr.String())
		}
	})

	t.Run("a client key without its certificate is rejected at startup", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--key", keyFile}, io.Discard, &stderr)
		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "client cert and key must be provided together") {
			t.Errorf("stderr %q does not reject the unpaired client key", stderr.String())
		}
	})

	t.Run("a client certificate with its key is accepted at startup", func(t *testing.T) {
		srv := newPlainDocServer(t)
		var stdout, stderr bytes.Buffer
		code, _ := run([]string{
			"--url", srv.URL,
			"--cacert", certFile,
			"--cert", certFile,
			"--key", keyFile,
			"--dry-run",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Errorf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
		}
	})
}

// TestRunFetchTimeoutFlag: the fetch timeout is configurable with
// bandaid's default (10s).
func TestRunFetchTimeoutFlag(t *testing.T) {
	srv := newPlainDocServer(t)
	tests := []struct {
		name  string
		extra []string
		want  time.Duration
	}{
		{"the fetch timeout defaults to bandaid's ten seconds", nil, 10 * time.Second},
		{"the fetch timeout is configurable", []string{"--fetch-timeout", "2s"}, 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(slices.Clone(tt.extra), "--url", srv.URL, "--dry-run")
			code, opts := run(args, &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
			}
			if opts.fetchTimeout != tt.want {
				t.Errorf("fetch timeout = %v, want %v", opts.fetchTimeout, tt.want)
			}
		})
	}
}

// TestRunHasNoInsecureMode: there is no insecure-skip-verify mode —
// such a flag is not part of the command line at all.
func TestRunHasNoInsecureMode(t *testing.T) {
	var stderr bytes.Buffer
	code, _ := run([]string{"--insecure-skip-verify", "--url", "http://127.0.0.1:1/report"}, io.Discard, &stderr)
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "unknown flag: --insecure-skip-verify") {
		t.Errorf("stderr %q does not reject the insecure flag", stderr.String())
	}
}
