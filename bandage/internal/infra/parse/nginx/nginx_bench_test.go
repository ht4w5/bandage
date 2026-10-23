package nginx

import (
	"testing"

	"github.com/HT4w5/webmedkit/bandage/internal/bench"
)

// BenchmarkParse measures Parser.Parse per line shape; lines are pre-converted
// to []byte so the timed region is Parse alone. One op is one raw log line.
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
