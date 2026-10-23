package bench

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// ReportLinesPerSec reports the benchmark's throughput as lines/s; meaningful
// where one op is one raw log line. Call it after the b.Loop() loop.
func ReportLinesPerSec(b *testing.B, lines int) {
	b.Helper()
	b.ReportMetric(linesPerSec(lines, b.Elapsed()), "lines/s")
}

// linesPerSec is the rate ReportLinesPerSec reports; zero when no time
// elapsed (never +Inf).
func linesPerSec(lines int, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(lines) / elapsed.Seconds()
}

// ListenAddr returns the ingest listen address for network: a unixgram socket
// under tb's temp dir, or a probed free loopback port for tcp (fixed address).
func ListenAddr(tb testing.TB, network string) string {
	tb.Helper()
	switch network {
	case "unixgram":
		return filepath.Join(tb.TempDir(), "log.sock")
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			tb.Fatalf("probe tcp port: %v", err)
		}
		addr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			tb.Fatalf("close tcp probe: %v", err)
		}
		return addr
	default:
		tb.Fatalf("ListenAddr: unknown network %q", network)
		return ""
	}
}
