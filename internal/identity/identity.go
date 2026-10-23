// Package identity is the build identity of a binary built from this
// tree: a program name supplied at compile time plus the four
// linker-injected values (make build -ldflags -X).
package identity

import (
	"fmt"
	"runtime"
	"strconv"
)

// Linker-injected values (Makefile -ldflags -X). Zero values mark a
// non-release build: version falls back to "dev". The program name is
// never stamped: each command passes it at compile time via For.
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
	dirtyFlag = ""
)

var (
	goVersion = runtime.Version()
	platform  = runtime.GOOS + "/" + runtime.GOARCH
)

// Build is one program's build identity: its name (passed at compile
// time, never linker-stamped) and the stamps shared by every binary
// built from this tree.
type Build struct {
	name      string
	version   string
	commit    string
	buildDate string
	dirty     bool
	goVersion string
	platform  string
}

// For returns the build identity of the named program. The name is
// passed at compile time by the command; the stamps come from the
// linker injection shared by every binary built from this tree.
func For(name string) Build {
	dirty, _ := strconv.ParseBool(dirtyFlag)
	return Build{
		name:      name,
		version:   version,
		commit:    commit,
		buildDate: buildDate,
		dirty:     dirty,
		goVersion: goVersion,
		platform:  platform,
	}
}

// Name is the program name.
func (b Build) Name() string { return b.name }

// Version is the release version ("dev" for unreleased builds).
func (b Build) Version() string { return b.version }

// Commit is the short git commit the binary was built from.
func (b Build) Commit() string { return b.commit }

// BuildDate is the UTC build timestamp (RFC 3339), honoring SOURCE_DATE_EPOCH.
func (b Build) BuildDate() string { return b.buildDate }

// Dirty reports whether the binary was built from a modified tree.
func (b Build) Dirty() bool { return b.dirty }

// GoVersion is the Go toolchain version the binary was built with.
func (b Build) GoVersion() string { return b.goVersion }

// Platform is the target OS/architecture.
func (b Build) Platform() string { return b.platform }

// String is the one-line identity summary (`-v` output).
func (b Build) String() string {
	head := b.name + " " + b.version
	if b.commit != "" {
		head += " " + b.commit
		if b.dirty {
			head += "-dirty"
		}
	}
	if b.buildDate != "" {
		head += " " + b.buildDate
	}
	return fmt.Sprintf("%s (%s %s)", head, b.goVersion, b.platform)
}

// Header is the short identity (name, version, commit) for the `--test`
// plan banner.
func (b Build) Header() string {
	if b.commit != "" {
		return fmt.Sprintf("%s %s (%s)", b.name, b.version, b.commit)
	}
	return b.name + " " + b.version
}
