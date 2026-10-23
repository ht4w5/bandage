package firewall

import "github.com/spf13/pflag"

// Factory is a firewall driver's registration — the shape a driver
// registry holds and the command wires flags through: the driver's
// name, its own flag binding (its prefixed flag group), its startup
// validation, and the opening of its enforcement points. One driver
// serves a run: the factory expands its targeting (e.g. the nftables
// factory's nsfs paths) into one driver instance per enforcement
// point, and the engine iterates them — one fetch-compile serves them
// all and skip-if-unchanged follows each instance. Opening is lazy: no
// I/O happens until a driver method runs, so --dry-run needs no
// privileges. Targeting and enforcement scope bind inside the factory,
// never in engine flags: they are precisely what differs between
// enforcement surfaces (ADR 0012).
type Factory interface {
	// Name is the driver's registry name — the --firewall value that
	// selects it.
	Name() string

	// BindFlags binds the driver's own flags — its prefixed group — to
	// fs.
	BindFlags(fs *pflag.FlagSet)

	// Validate checks every bound flag value at startup and refuses a
	// broken configuration loudly.
	Validate() error

	// Open expands the configured targeting into the driver instances
	// enforcing at each point — the points the engine iterates.
	Open() ([]Point, error)
}
