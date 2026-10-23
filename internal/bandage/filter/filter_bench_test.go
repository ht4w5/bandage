package filter

import (
	"fmt"
	"testing"
)

// benchMatch sinks Match results so the calls cannot be elided.
var benchMatch bool

// leafCases pairs each leaf filter type with sources that do and do not match
// baseEvent.
var leafCases = []struct{ name, match, miss string }{
	{"remote-addr", `src 203.0.113.0/24`, `src 198.51.100.0/24`},
	{"method", `method GET`, `method POST`},
	{"path", `path "/releases/24.04.iso"`, `path "/releases/other.iso"`},
	{"path-prefix", `path prefix "/releases/"`, `path prefix "/other/"`},
	{"path-suffix", `path suffix ".iso"`, `path suffix ".img"`},
	{"path-keyword", `path keyword "24.04"`, `path keyword "debian"`},
	{"agent", `agent "curl/8.5.0"`, `agent "Wget/1.21"`},
	{"agent-keyword", `agent keyword "curl"`, `agent keyword "Wget"`},
	{"status", `status 200`, `status 404`},
	{"status-class", `status class 2`, `status class 5`},
	{"sent-at-least", `sent >= 1k`, `sent >= 10m`},
	{"sent-at-most", `sent <= 10k`, `sent <= 100`},
}

// benchFilter parses src or fails the benchmark: fixture construction is
// setup, never a silent zero filter.
func benchFilter(b *testing.B, src string) Filter {
	b.Helper()
	f, err := Parse(src)
	if err != nil {
		b.Fatalf("Parse(%q): %v", src, err)
	}
	return f
}

// benchChain builds n realistic rule filters (site CIDR, method, path prefix,
// minimum size); the last matches baseEvent exactly when matchLast is set.
func benchChain(b *testing.B, n int, matchLast bool) []Filter {
	b.Helper()
	filters := make([]Filter, n)
	for i := range filters {
		prefix := fmt.Sprintf("/mirror/%d/", i)
		if matchLast && i == n-1 {
			prefix = "/releases/"
		}
		src := fmt.Sprintf(`src 203.0.113.0/24 and method GET and path prefix "%s" and sent >= 1k`, prefix)
		filters[i] = benchFilter(b, src)
	}
	return filters
}

func BenchmarkFilterMatch(b *testing.B) {
	ev := baseEvent()
	b.Run("leaf", func(b *testing.B) {
		for _, leaf := range leafCases {
			for _, path := range []struct {
				name string
				src  string
			}{{"match", leaf.match}, {"no-match", leaf.miss}} {
				b.Run(leaf.name+"/"+path.name, func(b *testing.B) {
					f := benchFilter(b, path.src)
					for b.Loop() {
						benchMatch = f.Match(&ev)
					}
				})
			}
		}
	})
	b.Run("chain", func(b *testing.B) {
		for _, n := range []int{1, 10, 100} {
			for _, path := range []struct {
				name      string
				matchLast bool
			}{{"match", true}, {"no-match", false}} {
				filters := benchChain(b, n, path.matchLast)
				b.Run(fmt.Sprintf("%d-rules/%s", n, path.name), func(b *testing.B) {
					for b.Loop() {
						matched := false
						for _, f := range filters {
							if f.Match(&ev) {
								matched = true
								break // terminal rule: chain traversal ends
							}
						}
						benchMatch = matched
					}
				})
			}
		}
	})
}
