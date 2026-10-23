// Package identity is the build identity of the running binary: the
// program name plus the four linker-injected values (make build -ldflags -X).
package identity

import (
	"fmt"
	"runtime"
	"strconv"
)

// Name is the program name.
const Name = "bandage"

// Linker-injected values (Makefile -ldflags -X). Zero values mark a
// non-release build: version falls back to "dev".
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
	dirtyFlag = ""
)

var (
	dirty     bool
	goVersion = runtime.Version()
	platform  = runtime.GOOS + "/" + runtime.GOARCH
)

// Derived strings, computed once at init.
var (
	summary string
	header  string
)

func init() {
	if b, err := strconv.ParseBool(dirtyFlag); err == nil {
		dirty = b
	}
	summary = buildSummary(Name)
	header = buildHeader()
}

// Version is the release version ("dev" for unreleased builds).
func Version() string { return version }

// Commit is the short git commit the binary was built from.
func Commit() string { return commit }

// BuildDate is the UTC build timestamp (RFC 3339), honoring SOURCE_DATE_EPOCH.
func BuildDate() string { return buildDate }

// Dirty reports whether the binary was built from a modified tree.
func Dirty() bool { return dirty }

// GoVersion is the Go toolchain version the binary was built with.
func GoVersion() string { return goVersion }

// Platform is the target OS/architecture.
func Platform() string { return platform }

// String is the one-line identity summary (`-v` output), computed once at init.
func String() string { return summary }

// Summary is the one-line identity summary for a named program sharing
// these linker-injected values: the second command prints
// Summary("splint") off the same stamp.
func Summary(name string) string { return buildSummary(name) }

// Header is the short identity (name, version, commit) for `--test` and `-h`.
func Header() string { return header }

func buildSummary(name string) string {
	head := name + " " + version
	if commit != "" {
		head += " " + commit
		if dirty {
			head += "-dirty"
		}
	}
	if buildDate != "" {
		head += " " + buildDate
	}
	return fmt.Sprintf("%s (%s %s)", head, goVersion, platform)
}

func buildHeader() string {
	if commit != "" {
		return fmt.Sprintf("%s %s (%s)", Name, version, commit)
	}
	return Name + " " + version
}
