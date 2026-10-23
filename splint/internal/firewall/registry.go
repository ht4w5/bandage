package firewall

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// Registry is the firewall-driver registry --firewall selects from:
// the factories registered for this binary plus the selection
// semantics of the command surface (see Select) and the
// flag-ownership grouping the usage output renders (see Groups). One
// firewall driver serves a whole run — no per-point driver mixing.
type Registry struct {
	factories []Factory
	groups    []Group // flag ownership in registration order, recorded by Bind
}

// Group is one flag owner's group: a driver's registry name and the
// flag names its BindFlags bound. Engine flags are those in no group.
type Group struct {
	Owner string
	Flags []string
}

// NewRegistry returns a registry holding factories in registration
// order.
func NewRegistry(factories ...Factory) *Registry {
	return &Registry{factories: factories}
}

// Names returns the accepted --firewall values, in registration order.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.factories))
	for _, f := range r.factories {
		names = append(names, f.Name())
	}
	return names
}

// Bind binds every factory's flag group to fs and records which flag
// names each factory owns — the grouping the usage output renders and
// the ownership Select refuses unselected-driver flags by.
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

// Groups returns the flag groups by owner, in registration order.
func (r *Registry) Groups() []Group { return r.groups }

// Select returns the factory the --firewall value names — the one
// driver serving the whole run — refusing an unknown value with the
// known drivers listed, and refusing an explicitly set flag belonging
// to an unselected driver (pflag's Changed semantics).
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
