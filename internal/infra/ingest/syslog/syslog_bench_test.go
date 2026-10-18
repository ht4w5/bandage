package syslog

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/bench"
)

// BenchmarkIngestForward measures the isolated ingest forwarding cost
// (spec hot-path inventory, stage 1): go-syslog's receive/scan/framing
// plus Source.run's extractLine and forward onto the out channel, with
// no parser, enrichment or evaluation attached — the consumer drains
// and counts (the pipeline's d.lines handoff, unbuffered). One op is
// one raw log line fed; lines/s is reported. The socket decouples the
// feed from forwarding (parts buffer + kernel buffers), so the final
// drain runs inside the timed region: every counted line is forwarded
// before the timer stops.
func BenchmarkIngestForward(b *testing.B) {
	for _, network := range []string{"tcp", "unixgram"} {
		b.Run(network, func(b *testing.B) {
			corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistUniform, 1024)
			wire := make([][]byte, corpus.Len())
			for i := range wire {
				line := corpus.Line(i)
				if network == "tcp" {
					line += "\n" // tcp frames one line per write (the e2e send convention)
				}
				wire[i] = []byte(line)
			}

			out := make(chan string) // unbuffered: the production handoff
			var forwarded atomic.Int64
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				for range out {
					forwarded.Add(1)
				}
			}()

			src := New(network, bench.ListenAddr(b, network), out, zerolog.Nop())
			if err := src.Start(); err != nil {
				b.Fatalf("Start: %v", err)
			}
			conn, err := net.Dial(network, src.addr)
			if err != nil {
				b.Fatalf("dial %s: %v", network, err)
			}
			b.Cleanup(func() {
				conn.Close()
				if err := src.Shutdown(); err != nil {
					b.Errorf("Shutdown: %v", err)
				}
				close(out) // Shutdown drained every producer, so no senders remain.
				<-drained
			})

			var lines int
			for b.Loop() {
				if _, err := conn.Write(wire[lines%len(wire)]); err != nil {
					b.Fatalf("send: %v", err)
				}
				lines++
			}
			b.StartTimer()
			waitForwarded(b, &forwarded, lines)
			b.StopTimer()
			bench.ReportLinesPerSec(b, lines)
		})
	}
}

// waitForwarded blocks until n lines have been forwarded on out, or
// fails b after a generous deadline. It is called inside the timed
// region, so the poll interval bounds the drain's accounting error.
func waitForwarded(tb testing.TB, forwarded *atomic.Int64, n int) {
	tb.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for forwarded.Load() < int64(n) {
		if time.Now().After(deadline) {
			tb.Fatalf("forwarded %d of %d lines", forwarded.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}
