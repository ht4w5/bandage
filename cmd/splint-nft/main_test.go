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

// newDocServerBody is the report endpoint serving one fixed document
// body — a whole report document fixture.
func newDocServerBody(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body) // error ignored: tests assert the outcome
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newPlainDocServer is the plain-HTTP report endpoint: one empty
// version-0 document, enough to complete a --dry-run startup.
func newPlainDocServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newDocServerBody(t, `{"version":0,"generated_at":"2025-10-17T18:00:00Z","reports":[]}`)
}

// reportDocFor is a one-record version-0 report document: the minimal
// fixture for flag behavior that lands in the compiled ban rules.
func reportDocFor(target string) string {
	return `{"version":0,"generated_at":"2025-10-17T18:00:00Z","reports":[{"rule":"r","chain":"c","reason":"x","target":"` + target + `","penalty":{"action":"drop"}}]}`
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

// TestRunExclusionFlags: the --exclude-prefix surface — operator
// exclusions are repeatable, validated at startup and subtracted from
// every ban set (this one flag subsumes bandaid's whitelist and
// fluxc's exclude-prefix surfaces).
func TestRunExclusionFlags(t *testing.T) {
	t.Run("an unparseable exclusion prefix is rejected at startup", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--exclude-prefix", "not-a-prefix"}, io.Discard, &stderr)
		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "exclude prefix") {
			t.Errorf("stderr %q does not reject the unparseable exclusion prefix", stderr.String())
		}
	})

	t.Run("exclusion prefixes are repeatable", func(t *testing.T) {
		srv := newPlainDocServer(t)
		var stdout, stderr bytes.Buffer
		code, opts := run([]string{
			"--url", srv.URL,
			"--exclude-prefix", "203.0.113.0/24",
			"--exclude-prefix", "198.51.100.7",
			"--dry-run",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
		}
		if want := []string{"203.0.113.0/24", "198.51.100.7"}; !slices.Equal(opts.excludePrefix, want) {
			t.Errorf("exclude prefixes = %v, want %v", opts.excludePrefix, want)
		}
	})

	t.Run("a bare-address exclusion excludes its host prefix from every ban set", func(t *testing.T) {
		srv := newDocServerBody(t, reportDocFor("203.0.113.7/32"))
		var stdout, stderr bytes.Buffer
		code, _ := run([]string{
			"--url", srv.URL,
			"--exclude-prefix", "203.0.113.7",
			"--dry-run",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
		}
		if stdout.String() != "[]\n" {
			t.Errorf("--dry-run output = %q, want the fully excluded Target to compile to no ban rule", stdout.String())
		}
	})
}

// TestRunExcludePrivateFlag: the RFC1918 and ULA exclusions — on by
// default, opted out with --exclude-private=false for hosts whose
// clients live in private space.
func TestRunExcludePrivateFlag(t *testing.T) {
	t.Run("private-space Targets are excluded by default", func(t *testing.T) {
		srv := newDocServerBody(t, reportDocFor("10.1.2.3/32"))
		var stdout, stderr bytes.Buffer
		code, opts := run([]string{"--url", srv.URL, "--dry-run"}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
		}
		if !opts.excludePrivate {
			t.Error("--exclude-private defaults to false, want true")
		}
		if stdout.String() != "[]\n" {
			t.Errorf("--dry-run output = %q, want the private Target excluded by default", stdout.String())
		}
	})

	t.Run("the opt-out admits private-space Targets", func(t *testing.T) {
		srv := newDocServerBody(t, reportDocFor("10.1.2.3/32"))
		var stdout, stderr bytes.Buffer
		code, opts := run([]string{"--url", srv.URL, "--exclude-private=false", "--dry-run"}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
		}
		if opts.excludePrivate {
			t.Error("--exclude-private=false still excludes private space")
		}
		if !strings.Contains(stdout.String(), "10.1.2.3/32") {
			t.Errorf("--dry-run output %q does not compile the private Target under the opt-out", stdout.String())
		}
	})
}

// TestRunServicePrefilterFlags: the service prefilter surface — the
// destination ports and addresses every ban rule leads with, both
// repeatable and validated at startup.
func TestRunServicePrefilterFlags(t *testing.T) {
	t.Run("a non-numeric service port is a usage error", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--service-port", "https"}, io.Discard, &stderr)
		if code != exitUsage {
			t.Errorf("exit code = %d, want %d", code, exitUsage)
		}
	})

	t.Run("a service port above the port range is rejected at startup", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--service-port", "70000"}, io.Discard, &stderr)
		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "service port") {
			t.Errorf("stderr %q does not reject the out-of-range service port", stderr.String())
		}
	})

	t.Run("a service port of zero is rejected at startup", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--service-port", "0"}, io.Discard, &stderr)
		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "service port") {
			t.Errorf("stderr %q does not reject the zero service port", stderr.String())
		}
	})

	t.Run("an unparseable service address is rejected at startup", func(t *testing.T) {
		var stderr bytes.Buffer
		code, _ := run([]string{"--url", "http://127.0.0.1:1/report", "--service-address", "not-an-address"}, io.Discard, &stderr)
		if code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "service address") {
			t.Errorf("stderr %q does not reject the unparseable service address", stderr.String())
		}
	})

	t.Run("service ports and addresses are repeatable and resolve", func(t *testing.T) {
		srv := newPlainDocServer(t)
		var stdout, stderr bytes.Buffer
		code, opts := run([]string{
			"--url", srv.URL,
			"--service-port", "53",
			"--service-port", "443",
			"--service-address", "203.0.113.5",
			"--service-address", "2001:db8::5/128",
			"--dry-run",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
		}
		if want := []uint16{53, 443}; !slices.Equal(opts.servicePort, want) {
			t.Errorf("service ports = %v, want %v", opts.servicePort, want)
		}
		if want := []string{"203.0.113.5", "2001:db8::5/128"}; !slices.Equal(opts.serviceAddress, want) {
			t.Errorf("service addresses = %v, want %v", opts.serviceAddress, want)
		}
	})
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

// TestRunValidatesTheNamespacePaths: the repeatable --netns flag
// selects target namespaces — every value must be a non-empty,
// distinct nsfs path — and without the flag the current namespace is
// the target.
func TestRunValidatesTheNamespacePaths(t *testing.T) {
	srv := newPlainDocServer(t)
	tests := []struct {
		name      string
		extra     []string
		wantCode  int
		wantErr   string
		wantNetNS []string
	}{
		{
			name:     "an empty --netns value is rejected at startup",
			extra:    []string{"--netns", ""},
			wantCode: exitError,
			wantErr:  "netns: namespace path must not be empty",
		},
		{
			name:     "a duplicate --netns value is rejected at startup",
			extra:    []string{"--netns", "/var/run/netns/a", "--netns", "/var/run/netns/a"},
			wantCode: exitError,
			wantErr:  `netns: duplicate namespace path "/var/run/netns/a"`,
		},
		{
			name:      "distinct --netns values are accepted at startup",
			extra:     []string{"--netns", "/var/run/netns/a", "--netns", "/var/run/netns/b"},
			wantCode:  exitOK,
			wantNetNS: []string{"/var/run/netns/a", "/var/run/netns/b"},
		},
		{
			name:      "without --netns the current namespace is the target",
			wantCode:  exitOK,
			wantNetNS: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(slices.Clone(tt.extra), "--url", srv.URL, "--dry-run")
			code, opts := run(args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr %q)", code, tt.wantCode, stderr.String())
			}
			if tt.wantErr != "" {
				if !strings.Contains(stderr.String(), tt.wantErr) {
					t.Errorf("stderr %q does not contain %q", stderr.String(), tt.wantErr)
				}
				return
			}
			if !slices.Equal(opts.netns, tt.wantNetNS) {
				t.Errorf("netns = %v, want %v", opts.netns, tt.wantNetNS)
			}
		})
	}
}
