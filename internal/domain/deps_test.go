package bandage

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The domain dependency rule (spec: Architecture; PLAN §3): domain
// modules depend only on the domain core and the standard library. This
// lint parses every Go file under internal/domain — test files included
// — and rejects imports of any domain submodule. Run from this package's
// directory, "." is the domain core and each subdirectory a module.
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
			if p != domainPath && strings.HasPrefix(p, domainPath+"/") {
				t.Errorf("%s imports sibling domain module %s (modules may depend only on the domain core and the standard library)", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
