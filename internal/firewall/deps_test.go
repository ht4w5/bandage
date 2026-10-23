package firewall

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestModulesDependOnlyOnTheSeam enforces the module shape's dependency
// rule (the spec's Module shape): the engine (internal/splint) and the
// drivers (the firewall seam's subpackages — the nftables driver and
// the recording stub) both depend on the seam and never on each other —
// the engine never imports a driver. Test files are outside the rule:
// the engine's update-cycle suite drives the recording stub by
// design (the spec's seam-1 test surface).
func TestModulesDependOnlyOnTheSeam(t *testing.T) {
	const (
		engine = "github.com/HT4w5/bandage/internal/splint"
		seam   = "github.com/HT4w5/bandage/internal/firewall"
	)
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(path), "../"))
		kind := "" // "" = not part of the module shape's rule
		switch {
		case rel == "splint" || strings.HasPrefix(rel, "splint/"):
			kind = "engine"
		case strings.HasPrefix(rel, "firewall/nft/") || strings.HasPrefix(rel, "firewall/firewalltest/"):
			kind = "driver"
		default:
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
			switch kind {
			case "engine":
				if p != seam && (strings.HasPrefix(p, seam+"/") || strings.HasPrefix(p, engine+"/")) {
					t.Errorf("%s imports the driver package %s (the engine imports the seam %s only, never a driver package)", path, p, seam)
				}
			case "driver":
				if p == engine || strings.HasPrefix(p, engine+"/") {
					t.Errorf("%s imports the engine %s (drivers depend on the seam %s only)", path, p, seam)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
