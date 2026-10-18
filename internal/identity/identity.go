// Package identity is the build identity of the running binary: the
// program name plus the four linker-injected values (version, commit,
// build date, dirty flag) injected by `make build` via -ldflags -X.
//
// All derived strings (the one-line summary and the short header) are
// computed once at init; accessors expose the raw values. There is
// deliberately no user-agent helper — bandage makes no outbound HTTP
// requests. The identity surfaces in four places — `-v` output, the
// startup log record's fields, the `/stats` build block, and the
// `--test` plan header — and the short header also heads the `-h`
// usage text (the spec's "exactly four" misses that fifth consumer of
// the header).
package identity

import (
	"fmt"
	"runtime"
	"strconv"
)

// Name is the program name.
const Name = "bandage"

// Linker-injected values (Makefile: -X .../internal/identity.<var>=...).
// The zero value of each marks a non-release build (e.g. plain `go
// build`): version falls back to "dev", the empty strings stay empty.
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

// Derived strings, computed once at init (spec: Implementation
// Decisions).
var (
	summary string
	header  string
)

func init() {
	if b, err := strconv.ParseBool(dirtyFlag); err == nil {
		dirty = b
	}
	summary = buildSummary()
	header = buildHeader()
}

// Version is the release version ("dev" for unreleased builds).
func Version() string { return version }

// Commit is the short git commit the binary was built from.
func Commit() string { return commit }

// BuildDate is the UTC build timestamp (RFC 3339), honoring
// SOURCE_DATE_EPOCH for reproducible builds.
func BuildDate() string { return buildDate }

// Dirty reports whether the binary was built from a modified tree.
func Dirty() bool { return dirty }

// GoVersion is the Go toolchain version the binary was built with.
func GoVersion() string { return goVersion }

// Platform is the target OS/architecture.
func Platform() string { return platform }

// String is the one-line identity summary (`-v` output): name, version,
// commit (with dirty marker), build date, Go version and platform.
// Computed once at init.
func String() string { return summary }

// Header is the short identity (name, version, commit) heading the
// `--test` plan output and the `-h` usage text. Computed once at init.
func Header() string { return header }

func buildSummary() string {
	head := Name + " " + version
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
