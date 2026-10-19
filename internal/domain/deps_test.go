package bandage

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDomainModulesDependOnlyOnCore enforces the dependency rule
// (ADR 0005): domain modules import only the stdlib and the domain core.
func TestDomainModulesDependOnlyOnCore(t *testing.T) {
	const domainPath = "github.com/HT4w5/bandage/internal/domain"
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			switch {
			case p == domainPath:
			case strings.HasPrefix(p, domainPath+"/"):
				t.Errorf("%s imports sibling domain module %s (modules may depend only on the domain core and the standard library)", path, p)
			case p == "C" || strings.Contains(strings.SplitN(p, "/", 2)[0], "."):
				t.Errorf("%s imports non-stdlib package %s (modules may depend only on the domain core and the standard library)", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
