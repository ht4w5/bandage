package firewall

import "github.com/spf13/pflag"

// Factory is a firewall driver's registration: its registry name, its
// own flag binding (its prefixed flag group), its startup validation,
// and the opening of its enforcement points. One driver serves a run:
// Open expands the factory's targeting into one driver instance per
// enforcement point. Opening is lazy — no I/O until a driver method
// runs, so --dry-run needs no privileges. Targeting binds in the
// factory, never in engine flags (ADR 0012).
type Factory interface {
	// Name is the driver's registry name — the --firewall value that
	// selects it.
	Name() string

	// BindFlags binds the driver's own flag group to fs.
	BindFlags(fs *pflag.FlagSet)

	// Validate checks every bound flag value at startup and refuses a
	// broken configuration loudly.
	Validate() error

	// Open expands the configured targeting into one driver instance
	// per enforcement point — the points the engine iterates.
	Open() ([]Point, error)
}
