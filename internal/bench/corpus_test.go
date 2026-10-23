package bench

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/HT4w5/bandage/internal/bandage"
	"github.com/HT4w5/bandage/internal/infra/parse/nginx"
)

// Corpus tests pin generator determinism, key distributions, line shapes and
// the parser seam (every fixture line parses to exactly its Event).

// The four published splitmix64 reference vectors for a zero state.
var splitmix64Vectors = []uint64{
	0xe220a8397b1dcdaf,
	0x6e789e6aa1b965f4,
	0x06c45d188009454f,
	0xf88bb8a8724c81ec,
}

func TestRNGMatchesSplitmix64Reference(t *testing.T) {
	r := &rng{}
	for i, want := range splitmix64Vectors {
		if got := r.next(); got != want {
			t.Fatalf("next() #%d = %016x, want %016x", i, got, want)
		}
	}
}

func TestCorpusIsDeterministic(t *testing.T) {
	for _, shape := range []LineShape{ShapeMinimal, ShapeFull} {
		for _, dist := range []KeyDist{DistUniform, DistZipf, DistHot} {
			a := NewCorpus(Seed, shape, dist, 64)
			b := NewCorpus(Seed, shape, dist, 64)
			if a.Len() != b.Len() {
				t.Fatalf("NewCorpus(%s, %s) sizes %d and %d differ", shape, dist, a.Len(), b.Len())
			}
			for i := 0; i < a.Len(); i++ {
				if a.Line(i) != b.Line(i) {
					t.Fatalf("NewCorpus(%s, %s) line %d differs for the same seed:\n%s\n%s", shape, dist, i, a.Line(i), b.Line(i))
				}
				if a.Event(i) != b.Event(i) {
					t.Fatalf("NewCorpus(%s, %s) event %d differs for the same seed", shape, dist, i)
				}
			}
		}
	}

	a := NewCorpus(Seed, ShapeFull, DistZipf, 64)
	b := NewCorpus(Seed+1, ShapeFull, DistZipf, 64)
	diverges := false
	for i := 0; i < a.Len(); i++ {
		if a.Line(i) != b.Line(i) {
			diverges = true
			break
		}
	}
	if !diverges {
		t.Fatal("corpora for different seeds are identical")
	}
}

func TestCorpusLinesAndEventsCycle(t *testing.T) {
	c := NewCorpus(Seed, ShapeFull, DistZipf, 8)
	for i := 0; i < c.Len(); i++ {
		if got, want := c.Line(c.Len()+i), c.Line(i); got != want {
			t.Errorf("Line(%d) = %q, want wrapped Line(%d) = %q", c.Len()+i, got, i, want)
		}
		if got, want := c.Event(c.Len()+i), c.Event(i); got != want {
			t.Errorf("Event(%d) = %+v, want wrapped Event(%d) = %+v", c.Len()+i, got, i, want)
		}
	}
}

func TestCorpusLinesParseToTheirEvents(t *testing.T) {
	p := nginx.New()
	for _, shape := range []LineShape{ShapeMinimal, ShapeFull} {
		for _, dist := range []KeyDist{DistUniform, DistZipf, DistHot} {
			c := NewCorpus(Seed, shape, dist, 64)
			for i := 0; i < c.Len(); i++ {
				got, err := p.Parse([]byte(c.Line(i)))
				if err != nil {
					t.Fatalf("Parse(%s/%s line %d) dropped a fixture line: %v (line %q)", shape, dist, i, err, c.Line(i))
				}
				if want := c.Event(i); got != want {
					t.Fatalf("Parse(%s/%s line %d) = %+v, want Event %+v", shape, dist, i, got, want)
				}
			}
		}
	}
}

func TestCorpusMinimalLinesHaveOnlyRequiredFields(t *testing.T) {
	want := []string{"client", "method", "sent", "status", "time", "url"}
	c := NewCorpus(Seed, ShapeMinimal, DistUniform, 16)
	for i := 0; i < c.Len(); i++ {
		var fields map[string]any
		if err := json.Unmarshal([]byte(c.Line(i)), &fields); err != nil {
			t.Fatalf("line %d is not a JSON object: %v", i, err)
		}
		got := make([]string, 0, len(fields))
		for k := range fields {
			got = append(got, k)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("minimal line %d fields = %v, want exactly %v", i, got, want)
		}
	}
}

func TestCorpusFullLinesAddOptionalAndUnknownFields(t *testing.T) {
	c := NewCorpus(Seed, ShapeFull, DistUniform, 16)
	for i := 0; i < c.Len(); i++ {
		var fields map[string]any
		if err := json.Unmarshal([]byte(c.Line(i)), &fields); err != nil {
			t.Fatalf("line %d is not a JSON object: %v", i, err)
		}
		for _, k := range []string{"time", "client", "server", "method", "url", "duration", "host", "status", "sent", "agent", "extra"} {
			if _, ok := fields[k]; !ok {
				t.Errorf("full line %d is missing field %q", i, k)
			}
		}
		if ev := c.Event(i); ev.Agent == "" {
			t.Errorf("full line %d has an empty Agent, want the rendered agent", i)
		}
	}
}

// keyCounts tallies paths and client IPs over the whole corpus.
func keyCounts(c *Corpus) (paths, clients map[string]int) {
	paths, clients = make(map[string]int), make(map[string]int)
	for i := 0; i < c.Len(); i++ {
		ev := c.Event(i)
		paths[ev.Path]++
		clients[ev.RemoteAddr.String()]++
	}
	return paths, clients
}

func TestCorpusUniformKeysCoverTheirPools(t *testing.T) {
	const n = 4096
	c := NewCorpus(Seed, ShapeMinimal, DistUniform, n)
	paths, clients := keyCounts(c)
	for name, counts := range map[string]map[string]int{"path": paths, "client": clients} {
		if len(counts) < 200 {
			t.Errorf("uniform %s keys: %d distinct, want >= 200 of %d", name, len(counts), poolSize)
		}
		for k, cnt := range counts {
			if cnt > n/20 {
				t.Errorf("uniform %s key %q holds %d/%d lines, want <= %d", name, k, cnt, n, n/20)
			}
		}
	}
}

func TestCorpusZipfKeysSkewToTheHead(t *testing.T) {
	const n = 4096
	c := NewCorpus(Seed, ShapeMinimal, DistZipf, n)
	paths, clients := keyCounts(c)
	for _, check := range []struct {
		name   string
		counts map[string]int
		pool   [poolSize]string
	}{
		{name: "path", counts: paths, pool: pathPool},
		{name: "client", counts: clients, pool: clientPool},
	} {
		head, mid, tail := check.counts[check.pool[0]], check.counts[check.pool[31]], check.counts[check.pool[poolSize-1]]
		if head < n/20 {
			t.Errorf("zipf %s: hot key holds %d/%d lines, want >= %d", check.name, head, n, n/20)
		}
		if head < 10*mid {
			t.Errorf("zipf %s: hot key holds %d lines vs mid-rank %d, want hot >> mid", check.name, head, mid)
		}
		if head < 50*tail {
			t.Errorf("zipf %s: hot key holds %d lines vs tail %d, want hot >> tail", check.name, head, tail)
		}
	}
}

func TestCorpusHotPinsOneTrackerKey(t *testing.T) {
	// Every DistHot line maps to one tracker-cache key, so parallel
	// updates contend on one shard.
	c := NewCorpus(Seed, ShapeFull, DistHot, 64)
	first := ""
	for i := 0; i < c.Len(); i++ {
		ev := c.Event(i)
		if ev.Path != HotPath || ev.RemoteAddr.String() != HotIP {
			t.Fatalf("line %d = (%q, %v), want the hot pair (%q, %v)", i, ev.Path, ev.RemoteAddr, HotPath, HotIP)
		}
		target := bandage.DefaultTargetPrefix.Aggregate(ev.RemoteAddr).String()
		key := bandage.ReplayTrackerKey(target, ev.Path)
		if i == 0 {
			first = key
			continue
		}
		if key != first {
			t.Fatalf("line %d tracker key = %q, want the single hot key %q", i, key, first)
		}
	}
}

// benchmarkSink keeps generated corpora alive across iterations.
var benchmarkSink *Corpus

// BenchmarkCorpusBuild measures the fixture generator itself (one
// 1024-line full-shape Zipfian corpus per op).
func BenchmarkCorpusBuild(b *testing.B) {
	for b.Loop() {
		benchmarkSink = NewCorpus(Seed, ShapeFull, DistZipf, 1024)
	}
}
