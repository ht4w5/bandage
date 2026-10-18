// Package bench is the shared harness for the v0 benchmark suite
// (spec v0-benchmarks, Phase 0): a deterministic nginx-JSON line
// fixture corpus with controlled key distributions, and testing.B
// helpers. It is imported only by tests and benchmarks, never by
// production code.
//
// Corpus generation is deterministic by construction: a self-contained
// splitmix64 PRNG seeded per corpus, so the same arguments always yield
// byte-identical lines on every Go version and platform. Benchmarks
// build their corpus once before the b.Loop() loop and cycle it via
// Line/Event, so no fixture is ever rebuilt inside the timed region.
package bench

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Seed is the fixed seed every benchmark in the suite generates its
// fixtures from, so runs stay comparable across benchmarks and machines.
const Seed uint64 = 0x5eed

// LineShape selects the JSON shape of a generated nginx-JSON line
// (flux log format: escape=json, $msec/$remote_addr/$request_method/
// $uri/$status/$body_bytes_sent/$http_user_agent).
type LineShape int

const (
	// ShapeMinimal renders only the required fields: time, client,
	// method, url, status, sent. Its events have no agent.
	ShapeMinimal LineShape = iota
	// ShapeFull additionally renders the optional and reserved fields
	// (agent, host, server, duration) and an unknown field the parser
	// must ignore.
	ShapeFull
)

// String names the shape for benchmark sub-names.
func (s LineShape) String() string {
	if s == ShapeFull {
		return "full"
	}
	return "minimal"
}

// KeyDist selects how paths and client IPs — the tracker-cache key
// material — are distributed across a corpus.
type KeyDist int

const (
	// DistUniform draws paths and client IPs uniformly from their
	// pools: the spread-out baseline.
	DistUniform KeyDist = iota
	// DistZipf draws both Zipfian (weight 1/(rank+1)): a few hot keys
	// with a long tail, modelling hot Targets.
	DistZipf
	// DistHot pins every line to the one hot (path, client) pair: a
	// single tracker-cache key, forcing single-shard contention.
	DistHot
)

// String names the distribution for benchmark sub-names.
func (d KeyDist) String() string {
	switch d {
	case DistZipf:
		return "zipf"
	case DistHot:
		return "hot"
	default:
		return "uniform"
	}
}

// HotPath and HotIP are the hot (path, client) pair every DistHot line
// carries: one tracker-cache key, hence one shard under contention.
// They are also the head of both key pools, making them the hottest
// Zipfian keys as well.
const (
	HotPath = "/releases/24.04.iso"
	HotIP   = "203.0.113.7"
)

// poolSize is the number of distinct paths and of distinct client IPs
// a corpus draws its keys from. Both pools share one Zipf CDF, so the
// sizes must match.
const poolSize = 256

// Fixed field values of full-shape lines (the reserved and ignored
// fields of the flux log format).
const (
	fullServer   = "203.0.113.1"
	fullHost     = "example.org"
	fullDuration = "0.125"
	fullExtra    = "ignored" // unknown field the parser must ignore
)

// EpochSec is the $msec second of line 0; line i is EpochSec + i
// seconds later, so times are distinct and monotone across the corpus.
const EpochSec int64 = 1734345934

// Epoch is the fixture wall-clock origin every benchmark fixture keeps
// its event times and frozen clocks on (do not mutate). Packages the
// domain dependency lint keeps away from internal/bench
// (internal/domain/...) hold their own copy of this instant; keep the
// values identical.
var Epoch = time.Unix(EpochSec, 0).UTC()

var (
	// methods and statuses are the observed value pools: weighted by
	// repetition to look like real access logs.
	methods  = [...]string{"GET", "GET", "GET", "GET", "HEAD", "POST"}
	statuses = [...]int{200, 200, 200, 206, 304, 404, 403, 500, 502}
	agents   = [...]string{
		"Wget/1.21",
		"curl/8.5.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	}

	// pathPool and clientPool hold poolSize distinct keys, hottest
	// first: index 0 is the hot (path, client) pair, the tail is
	// generated.
	pathPool   = buildPool(HotPath, "/files/obj-%04d.bin")
	clientPool = buildPool(HotIP, "198.51.100.%d")

	// zipfCDF maps uniform draws to pool ranks with P(rank) ∝
	// 1/(rank+1) (Zipf s=1) via inverse transform.
	zipfCDF = buildZipfCDF(poolSize)
)

// buildPool fills a key pool: the hot key first, then generated keys.
func buildPool(hot, format string) [poolSize]string {
	var pool [poolSize]string
	pool[0] = hot
	for i := 1; i < poolSize; i++ {
		pool[i] = fmt.Sprintf(format, i)
	}
	return pool
}

// buildZipfCDF precomputes the cumulative P(rank) ∝ 1/(rank+1) over a
// pool of n ranks. Inverse transform over this fixed CDF keeps Zipfian
// draws stable by construction: they depend only on the PRNG stream.
func buildZipfCDF(n int) []float64 {
	cdf := make([]float64, n)
	var sum float64
	for r := range cdf {
		sum += 1 / float64(r+1)
		cdf[r] = sum
	}
	for r := range cdf {
		cdf[r] /= sum
	}
	cdf[n-1] = 1
	return cdf
}

// eventContent is the content of one fixture Event (GLOSSARY: Event —
// never "record"). It is the single source of truth for both
// renderings: the raw JSON line and the domain Event it parses to.
type eventContent struct {
	sec    int64 // $msec seconds
	msec   int64 // $msec fraction, milliseconds
	client string
	method string
	path   string
	status int
	sent   int64
	agent  string // empty for ShapeMinimal lines
}

// line renders the event content as one nginx-JSON access-log line.
func (ec eventContent) line(shape LineShape) string {
	t := fmt.Sprintf("%d.%03d", ec.sec, ec.msec)
	if shape == ShapeFull {
		return fmt.Sprintf(`{"time":%q,"client":%q,"server":%q,"method":%q,"url":%q,"duration":%q,"host":%q,"status":%d,"sent":%d,"agent":%q,"extra":%q}`,
			t, ec.client, fullServer, ec.method, ec.path, fullDuration, fullHost, ec.status, ec.sent, ec.agent, fullExtra)
	}
	return fmt.Sprintf(`{"time":%q,"client":%q,"method":%q,"url":%q,"status":%d,"sent":%d}`,
		t, ec.client, ec.method, ec.path, ec.status, ec.sent)
}

// event renders the content as the domain Event its line parses to
// (nginx.Parser field mapping).
func (ec eventContent) event() bandage.Event {
	return bandage.Event{
		Time:       time.Unix(ec.sec, ec.msec*int64(time.Millisecond)).UTC(),
		RemoteAddr: netip.MustParseAddr(ec.client),
		Method:     ec.method,
		Path:       ec.path,
		Agent:      ec.agent,
		Status:     ec.status,
		SentBytes:  ec.sent,
		SizeBytes:  bandage.FilesizeUnknown,
	}
}

// Corpus is a deterministic, pre-generated fixture set of raw
// nginx-JSON access-log lines and the events they parse to. All
// generation happens in NewCorpus; Line and Event only index the
// result, so benchmarks cycle them freely inside a b.Loop() loop.
type Corpus struct {
	lines  []string
	events []eventContent
}

// NewCorpus generates n fixture lines and their events for (seed,
// shape, dist): the same arguments always yield byte-identical output
// (pinned by TestCorpusIsDeterministic). n is clamped to at least 1.
//
// Benchmarks call it once before their b.Loop() loop and cycle the
// result with Line/Event — the corpus is never rebuilt per iteration.
func NewCorpus(seed uint64, shape LineShape, dist KeyDist, n int) *Corpus {
	if n < 1 {
		n = 1
	}
	r := &rng{state: seed}
	c := &Corpus{lines: make([]string, n), events: make([]eventContent, n)}
	for i := range c.events {
		// Two key draws per event content, always, so events line up
		// across distributions for a given seed.
		client := clientPool[drawKey(r.unit(), dist)]
		path := pathPool[drawKey(r.unit(), dist)]
		agent := agents[int(r.below(uint64(len(agents))))]
		if shape != ShapeFull {
			agent = "" // minimal lines carry no agent field
		}
		ec := eventContent{
			sec:    EpochSec + int64(i),
			msec:   int64(r.below(1000)),
			client: client,
			method: methods[int(r.below(uint64(len(methods))))],
			path:   path,
			status: statuses[int(r.below(uint64(len(statuses))))],
			sent:   int64(r.below(8_000_000)),
			agent:  agent,
		}
		c.events[i] = ec
		c.lines[i] = ec.line(shape)
	}
	return c
}

// Len is the corpus size.
func (c *Corpus) Len() int { return len(c.events) }

// Line returns the corpus's raw line for index i. i may be any
// non-negative counter: indices beyond Len wrap around, so a
// benchmark loop cycles the corpus without rebuilding it.
func (c *Corpus) Line(i int) string { return c.lines[i%len(c.lines)] }

// Event returns the domain Event line i parses to, on the same cycling
// index as Line. Parsing Line(i) yields exactly Event(i) (pinned by
// TestCorpusLinesParseToTheirEvents).
func (c *Corpus) Event(i int) bandage.Event { return c.events[i%len(c.events)].event() }

// drawKey maps a uniform draw to a pool index for dist.
func drawKey(u float64, dist KeyDist) int {
	switch dist {
	case DistZipf:
		// Rank of the first CDF entry >= u: P(rank) ∝ 1/(rank+1).
		rank, _ := slices.BinarySearch(zipfCDF, u)
		return rank
	case DistHot:
		return 0
	default:
		return int(u * float64(poolSize))
	}
}

// rng is a self-contained splitmix64 PRNG: fixture generation must
// yield identical corpora on every Go version and platform, so it
// depends on no external random stream. Its outputs are pinned by
// TestRNGMatchesSplitmix64Reference.
type rng struct{ state uint64 }

// next returns the next random word.
func (r *rng) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// unit draws a uniform float64 in [0, 1).
func (r *rng) unit() float64 {
	return float64(r.next()>>11) / float64(1<<53)
}

// below draws a uniform uint64 in [0, n). The modulo bias against
// 2^64 is negligible for fixture draws and keeps the stream simple.
func (r *rng) below(n uint64) uint64 { return r.next() % n }
