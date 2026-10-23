package firewall

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// Registry is the firewall-driver registry --firewall selects from:
// the factories registered for this binary plus the selection
// semantics of the command surface — the known driver names, the one
// driver that serves a whole run, and the refusal of an explicitly set
// flag that belongs to an unselected driver (pflag's Changed
// semantics: a mistyped combination fails loudly instead of silently
// not applying). The usage output groups flags by owner from the same
// ownership this registry records at Bind. There is no per-point
// driver mixing: Select returns the one factory whose Open expands
// into the run's every enforcement point.
type Registry struct {
	factories []Factory
	groups    []Group // flag ownership in registration order, recorded by Bind
}

// Group is one flag owner's group — a driver's registry name and the
// flag names its BindFlags bound. The usage output groups flags by
// owner: the engine's flags (those in no group) first, then each
// driver group.
type Group struct {
	Owner string
	Flags []string
}

// NewRegistry returns the registry holding factories in registration
// order — the order the usage output lists the driver groups in.
func NewRegistry(factories ...Factory) *Registry {
	return &Registry{factories: factories}
}

// Names returns the known driver names — the accepted --firewall
// values, in registration order. An unknown --firewall value fails
// with these listed.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.factories))
	for _, f := range r.factories {
		names = append(names, f.Name())
	}
	return names
}

// Bind binds every factory's flag group to fs and records which flag
// names each factory owns — the grouping the usage output renders and
// the ownership Select refuses unselected-driver flags by. Each
// factory binds its own prefixed group; the engine's flags are those
// outside every group.
func (r *Registry) Bind(fs *pflag.FlagSet) {
	r.groups = nil
	owned := make(map[string]bool)
	fs.VisitAll(func(f *pflag.Flag) { owned[f.Name] = true })
	for _, factory := range r.factories {
		factory.BindFlags(fs)
		var flags []string
		fs.VisitAll(func(f *pflag.Flag) {
			if !owned[f.Name] {
				owned[f.Name] = true
				flags = append(flags, f.Name)
			}
		})
		r.groups = append(r.groups, Group{Owner: factory.Name(), Flags: flags})
	}
}

// Groups returns the flag groups by owner, in registration order: one
// per registered driver, each with the flag names its factory bound.
// The usage output groups flags by owner from this.
func (r *Registry) Groups() []Group { return r.groups }

// Select returns the factory the --firewall value names — the one
// driver that serves the whole run — refusing an unknown value with
// the known drivers listed, and refusing an explicitly set flag that
// belongs to any unselected driver (pflag's Changed semantics: a
// mistyped combination fails loudly instead of silently not
// applying).
func (r *Registry) Select(name string, fs *pflag.FlagSet) (Factory, error) {
	var selected Factory
	for _, f := range r.factories {
		if f.Name() == name {
			selected = f
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("unknown firewall driver %q (known drivers: %s)", name, strings.Join(r.Names(), ", "))
	}
	for _, g := range r.groups {
		if g.Owner == name {
			continue
		}
		for _, flagName := range g.Flags {
			if fs.Changed(flagName) {
				return nil, fmt.Errorf("flag --%s belongs to the %s driver, not the selected %s driver", flagName, g.Owner, name)
			}
		}
	}
	return selected, nil
}
