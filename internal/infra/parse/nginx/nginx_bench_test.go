package nginx

import (
	"testing"

	"github.com/HT4w5/bandage/internal/bench"
)

// BenchmarkParse measures Parser.Parse per line shape (H1): the generic
// map unmarshal plus per-field re-parsing, reported as ns/op with
// -benchmem's B/op and allocs/op. Lines are pre-converted to []byte
// before the loop so the timed region is Parse alone (runPipeline's
// string→[]byte conversion is pipeline cost, not parse cost). Key
// distribution does not affect parsing, so the corpus is uniform. One
// op is one raw log line, so lines/s is reported too.
func BenchmarkParse(b *testing.B) {
	for _, shape := range []bench.LineShape{bench.ShapeMinimal, bench.ShapeFull} {
		b.Run(shape.String(), func(b *testing.B) {
			corpus := bench.NewCorpus(bench.Seed, shape, bench.DistUniform, 1024)
			lines := make([][]byte, corpus.Len())
			for i := range lines {
				lines[i] = []byte(corpus.Line(i))
			}
			p := New()
			var linesDone int
			for b.Loop() {
				if _, err := p.Parse(lines[linesDone%len(lines)]); err != nil {
					b.Fatalf("Parse: %v", err)
				}
				linesDone++
			}
			bench.ReportLinesPerSec(b, linesDone)
		})
	}
}
