package splint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/firewall"
	"github.com/HT4w5/bandage/internal/firewall/firewalltest"
)

// Primary seam: the transport — the update cycle driven against an
// HTTPS report endpoint that requires client certificates (mutual TLS,
// bandaid's --cacert/--cert/--key construction). The mutual-TLS
// success, the wrong-CA refusals (the cycle refuses and the last
// installed rules are kept) and the plain-HTTP case. There is no
// insecure mode: verification failures refuse the cycle, they never
// downgrade it.

// testPKI is the throwaway PKI the transport seam runs on: a CA whose
// certificates the HTTPS endpoint and the fetcher both trust (it signs
// the endpoint's and the good client's certificates), and a second CA
// for the wrong-CA refusals — its client certificate the endpoint does
// not accept, and its root does not verify the endpoint. Files are the
// PEM material the operator's runbook leaves on disk.
type testPKI struct {
	caPEM         []byte
	caFile        string // --cacert: the CA that signed the endpoint's certificate
	server        tls.Certificate
	certFile      string // --cert: the client certificate the endpoint accepts
	keyFile       string // --key: its key
	wrongCAFile   string // --cacert: a CA that signed nothing the endpoint presents
	wrongCertFile string // --cert: a client certificate from the wrong CA
	wrongKeyFile  string // --key: its key
}

// newTestPKI mints the throwaway PKI into a temp directory.
func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, caKey, caPEM := newCA(t, "splint test CA")
	wrongCA, wrongCAKey, wrongCAPEM := newCA(t, "splint wrong CA")

	serverCertPEM, serverKeyPEM := issue(t, ca, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "report endpoint"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	})
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "splint client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertPEM, clientKeyPEM := issue(t, ca, caKey, clientTmpl)
	wrongCertPEM, wrongKeyPEM := issue(t, wrongCA, wrongCAKey, clientTmpl)

	server, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	return &testPKI{
		caPEM:         caPEM,
		caFile:        writePEM(t, "ca.crt", caPEM),
		server:        server,
		certFile:      writePEM(t, "client.crt", clientCertPEM),
		keyFile:       writePEM(t, "client.key", clientKeyPEM),
		wrongCAFile:   writePEM(t, "wrong-ca.crt", wrongCAPEM),
		wrongCertFile: writePEM(t, "wrong-client.crt", wrongCertPEM),
		wrongKeyFile:  writePEM(t, "wrong-client.key", wrongKeyPEM),
	}
}

// newCA mints a throwaway CA: its certificate, key and certificate PEM.
func newCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// issue mints a certificate signed by ca per tmpl, with a fresh key:
// the certificate and key PEMs an operator would hold as --cert/--key.
func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// writePEM writes one PEM blob to the PKI directory and returns its
// path.
func writePEM(t *testing.T, name string, blob []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// newMutualTLSServer is the HTTPS report endpoint that requires client
// certificates: it presents the PKI's server certificate and accepts
// only client certificates signed by the PKI's CA.
func newMutualTLSServer(t *testing.T, pki *testPKI) *docServer {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.caPEM)
	return newDocServerTLS(t, &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	})
}

// newTransportUpdater wires the seam with the operator's fetch options:
// a real fetcher against the report endpoint, the recording stub driver
// and a capturing logger.
func newTransportUpdater(t *testing.T, rawURL string, opts ...Option) (*Updater, *firewalltest.Stub) {
	t.Helper()
	fetcher, err := NewFetcher(rawURL, opts...)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	stub := &firewalltest.Stub{}
	return New(fetcher, stub, defaultPolicy(), DefaultInterval, zerolog.New(&logCapture{})), stub
}

// TestUpdateCycleMutualTLS: the mutual-TLS success — an HTTPS endpoint
// that requires client certificates serves the report document to the
// operator's PKI (bandaid's --cacert verifies the server, --cert/--key
// present the client certificate), and the cycle compiles and installs
// it.
func TestUpdateCycleMutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	srv := newMutualTLSServer(t, pki)
	srv.serve(http.StatusOK, canonicalDoc(t))
	u, stub := newTransportUpdater(t, srv.URL, WithTLS(pki.caFile, pki.certFile, pki.keyFile))

	skips, err := u.Update(context.Background())
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(skips) != 0 {
		t.Errorf("skipped %d report records, want 0", len(skips))
	}
	assertInstalls(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
}

// TestUpdateCycleRefusesTheWrongCA: the wrong-CA failures — a cycle
// whose TLS material does not match the endpoint's PKI is refused and
// the last installed rules are kept.
func TestUpdateCycleRefusesTheWrongCA(t *testing.T) {
	pki := newTestPKI(t)
	srv := newMutualTLSServer(t, pki)
	srv.serve(http.StatusOK, canonicalDoc(t))

	// keepLast runs one successful mutual-TLS cycle and then a cycle with
	// badOpts, both on one driver so the last rules can be kept.
	keepLast := func(t *testing.T, badOpts ...Option) {
		t.Helper()
		stub := &firewalltest.Stub{}
		logs := &logCapture{}
		newUpdater := func(opts ...Option) *Updater {
			fetcher, err := NewFetcher(srv.URL, opts...)
			if err != nil {
				t.Fatalf("NewFetcher: %v", err)
			}
			return New(fetcher, stub, defaultPolicy(), DefaultInterval, zerolog.New(logs))
		}
		if _, err := newUpdater(WithTLS(pki.caFile, pki.certFile, pki.keyFile)).Update(context.Background()); err != nil {
			t.Fatalf("first Update: %v", err)
		}
		if _, err := newUpdater(badOpts...).Update(context.Background()); err == nil {
			t.Fatal("second Update succeeded, want an error")
		}
		assertInstalls(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		if stub.ResetCalls() != 0 {
			t.Errorf("Reset ran %d times, want 0", stub.ResetCalls())
		}
	}

	t.Run("a client certificate from the wrong CA refuses the cycle and keeps the last rules", func(t *testing.T) {
		keepLast(t, WithTLS(pki.caFile, pki.wrongCertFile, pki.wrongKeyFile))
	})
	t.Run("a CA that does not verify the endpoint refuses the cycle and keeps the last rules", func(t *testing.T) {
		keepLast(t, WithTLS(pki.wrongCAFile, pki.certFile, pki.keyFile))
	})
}

// TestUpdateCyclePlainHTTP: the plain-HTTP case — the localhost report
// endpoint keeps working with no TLS material at all.
func TestUpdateCyclePlainHTTP(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, canonicalDoc(t))
	u, stub := newTransportUpdater(t, srv.URL)

	if _, err := u.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertInstalls(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
}
