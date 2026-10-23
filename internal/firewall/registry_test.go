package firewall

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// Coverage: the command-run seam is deliberately untested — what would
// be asserted through the command is verified here, at the module
// that owns it.

type stubFactory struct {
	name   string
	flags  []string
	points []Point
	opened bool
}

func (f *stubFactory) Name() string { return f.name }

func (f *stubFactory) BindFlags(fs *pflag.FlagSet) {
	for _, name := range f.flags {
		fs.String(name, "", "the "+f.name+" driver's own flag")
	}
}

func (f *stubFactory) Validate() error { return nil }

func (f *stubFactory) Open() ([]Point, error) {
	f.opened = true
	return f.points, nil
}

// bindStubs registers the factories and parses args the way the
// command does.
func bindStubs(t *testing.T, args []string, factories ...Factory) (*Registry, *pflag.FlagSet) {
	t.Helper()
	r := NewRegistry(factories...)
	fs := pflag.NewFlagSet("splint", pflag.ContinueOnError)
	r.Bind(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return r, fs
}

func TestRegistrySelectsTheNamedDriver(t *testing.T) {
	alpha := &stubFactory{name: "alpha"}
	beta := &stubFactory{name: "beta"}
	r, fs := bindStubs(t, nil, alpha, beta)
	got, err := r.Select("beta", fs)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got != beta {
		t.Errorf("Select = %v, want the beta factory", got)
	}
}

func TestRegistryRefusesAnUnknownDriverListingTheKnownDrivers(t *testing.T) {
	r, fs := bindStubs(t, nil, &stubFactory{name: "alpha"}, &stubFactory{name: "beta"})
	if _, err := r.Select("gamma", fs); err == nil {
		t.Fatal("Select accepted the unknown driver gamma")
	} else {
		if !strings.Contains(err.Error(), `unknown firewall driver "gamma"`) {
			t.Errorf("Select error %q does not name the unknown driver", err)
		}
		if !strings.Contains(err.Error(), "alpha, beta") {
			t.Errorf("Select error %q does not list the known drivers", err)
		}
	}
}

func TestRegistryRefusesFlagsOfUnselectedDrivers(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		driver  string
		wantErr string
	}{
		{
			name:    "a flag of the unselected driver is refused",
			args:    []string{"--beta-one", "set"},
			driver:  "alpha",
			wantErr: "flag --beta-one belongs to the beta driver",
		},
		{
			name:   "a flag of the selected driver is accepted",
			args:   []string{"--alpha-one", "set"},
			driver: "alpha",
		},
		{
			name:   "unset flags of the unselected driver are inert",
			args:   nil,
			driver: "alpha",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, fs := bindStubs(t, tt.args,
				&stubFactory{name: "alpha", flags: []string{"alpha-one"}},
				&stubFactory{name: "beta", flags: []string{"beta-one"}},
			)
			_, err := r.Select(tt.driver, fs)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Select: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Select succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Select error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestRegistryGroupsFlagsByOwner(t *testing.T) {
	r := NewRegistry(
		&stubFactory{name: "alpha", flags: []string{"alpha-one", "alpha-two"}},
		&stubFactory{name: "beta", flags: []string{"beta-one"}},
	)
	fs := pflag.NewFlagSet("splint", pflag.ContinueOnError)
	fs.String("url", "", "the engine's own flag")
	r.Bind(fs)
	want := map[string]string{
		"alpha": "alpha-one,alpha-two",
		"beta":  "beta-one",
	}
	seen := make(map[string]bool)
	for _, g := range r.Groups() {
		seen[g.Owner] = true
		if got := strings.Join(g.Flags, ","); got != want[g.Owner] {
			t.Errorf("%s driver group = %q, want %q", g.Owner, got, want[g.Owner])
		}
	}
	if !seen["alpha"] || !seen["beta"] {
		t.Errorf("groups = %v, want one group per registered driver", r.Groups())
	}
}

func TestOneDriverServesTheWholeRun(t *testing.T) {
	alpha := &stubFactory{name: "alpha", points: []Point{{Label: "alpha-1"}, {Label: "alpha-2"}}}
	beta := &stubFactory{name: "beta", points: []Point{{Label: "beta-1"}}}
	r, fs := bindStubs(t, nil, alpha, beta)
	selected, err := r.Select("alpha", fs)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	points, err := selected.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var labels []string
	for _, p := range points {
		labels = append(labels, p.Label)
	}
	if strings.Join(labels, ",") != "alpha-1,alpha-2" {
		t.Errorf("points = %q, want every point of the selected alpha driver", labels)
	}
	if beta.opened {
		t.Error("the unselected beta driver was opened: one driver serves the whole run")
	}
}
