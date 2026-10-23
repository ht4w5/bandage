package nft

import (
	"fmt"
	"net/netip"
	"slices"

	flag "github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/firewall"
)

// Factory is the nftables firewall driver's registration: its name,
// its own --nft-* flag group, its startup validation, and the opening
// of its enforcement points. The flag group carries everything that
// differs between enforcement surfaces for this driver — where to
// enforce (the repeatable nsfs targeting) and what to police (the
// service prefilter's destination ports and addresses) — because
// targeting and enforcement scope are driver configuration, not engine
// flags (ADR 0012). The registry that selects one factory per run
// (firewall.Registry) is wired by the command; this factory binds and
// opens its own surface.
type Factory struct {
	// The bound flag values, resolved by Validate.
	hook      string
	netns     []string
	ports     []uint
	addresses []string

	// The validated hook and scope Open builds its drivers with.
	hookValue Hook
	prefilter Prefilter
}

var _ firewall.Factory = (*Factory)(nil)

// NewFactory returns the nftables factory with its flag defaults.
func NewFactory() *Factory {
	return &Factory{hook: string(HookInput)}
}

// Name is the driver's registry name — the --firewall value that
// selects it.
func (f *Factory) Name() string { return "nftables" }

// BindFlags binds the nftables driver's own flag group: the hook, the
// repeatable nsfs targeting, and the service prefilter's destination
// ports and addresses.
func (f *Factory) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.hook, "nft-hook", string(HookInput), "enforcement hook: input or prerouting")
	// Namespace values are literal nsfs paths, never comma lists —
	// hence StringArray, which unlike StringSlice keeps an empty value
	// visible to the validation below.
	fs.StringArrayVar(&f.netns, "nft-netns", nil, "target network namespace nsfs path (repeatable; default: the current namespace)")
	fs.UintSliceVar(&f.ports, "nft-service-port", nil, "service destination port the ban prefilter matches (repeatable)")
	fs.StringSliceVar(&f.addresses, "nft-service-address", nil, "service destination address or prefix the ban prefilter matches (repeatable)")
}

// Validate resolves and checks every bound flag value at startup — the
// hook, the namespace paths, the service ports and the service
// addresses — refusing a broken configuration loudly; the resolved
// hook and scope are what Open builds its drivers with.
func (f *Factory) Validate() error {
	hook, err := ParseHook(f.hook)
	if err != nil {
		return err
	}
	for i, path := range f.netns {
		if path == "" {
			return fmt.Errorf("netns: namespace path must not be empty (value %d)", i+1)
		}
		if slices.Contains(f.netns[:i], path) {
			return fmt.Errorf("netns: duplicate namespace path %q", path)
		}
	}
	ports := make([]uint16, 0, len(f.ports))
	for _, v := range f.ports {
		if v < 1 || v > 65535 {
			return fmt.Errorf("service port: must be between 1 and 65535 (got %d)", v)
		}
		ports = append(ports, uint16(v))
	}
	addrs := make([]netip.Prefix, 0, len(f.addresses))
	for _, v := range f.addresses {
		p, err := firewall.ParsePrefixOrAddr(v)
		if err != nil {
			return fmt.Errorf("service address: %w", err)
		}
		addrs = append(addrs, p)
	}
	f.hookValue, f.prefilter = hook, Prefilter{DstPorts: ports, DstAddrs: addrs}
	return nil
}

// Open expands the configured targeting into one driver instance per
// enforcement point — one per nsfs path, the current namespace when
// none is configured — each labeled with its path ("current" for the
// default target) and each carrying the configured enforcement scope.
// Opening is lazy: no I/O happens until a driver method runs, so
// --dry-run needs no privileges, and every apply re-opens its target
// so a recreated container is picked up through its stable handle.
func (f *Factory) Open() ([]firewall.Point, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	paths := f.netns
	if len(paths) == 0 {
		paths = []string{""}
	}
	points := make([]firewall.Point, 0, len(paths))
	for _, path := range paths {
		d, err := New(Config{Hook: f.hookValue, Prefilter: f.prefilter, NetNSPath: path})
		if err != nil {
			return nil, err
		}
		points = append(points, firewall.Point{Label: pointLabel(path), Driver: d})
	}
	return points, nil
}

// pointLabel is the enforcement point's opaque log label: the nsfs
// handle path, "current" for the default target. The engine logs it
// and never parses it.
func pointLabel(path string) string {
	if path == "" {
		return "current"
	}
	return path
}
