package bench

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// ReportLinesPerSec reports the benchmark's throughput as lines/s.
// Call it after the b.Loop() loop with the number of raw log lines the
// benchmark processed:
//
//	var lines int
//	for b.Loop() {
//		process(corpus.Line(lines))
//		lines++
//	}
//	bench.ReportLinesPerSec(b, lines)
//
// It is meaningful where one op is one raw log line (parse, whole
// pipeline); per-key microbenchmarks report ns/op instead.
func ReportLinesPerSec(b *testing.B, lines int) {
	b.Helper()
	b.ReportMetric(linesPerSec(lines, b.Elapsed()), "lines/s")
}

// linesPerSec is the rate ReportLinesPerSec reports: lines divided by
// elapsed benchmark time, zero when no time elapsed (never +Inf).
func linesPerSec(lines int, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(lines) / elapsed.Seconds()
}

// ListenAddr returns the ingest listen address for network: a socket
// path under tb's temp dir for unixgram, a probed free loopback port
// for tcp (go-syslog wants a fixed address, so the ephemeral port is
// reserved by a probe listener first — the freeAddr pattern). Shared
// here so every ingest benchmark binds sockets the same way.
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
