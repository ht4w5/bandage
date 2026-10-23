package identity

import (
	"strings"
	"testing"
)

// stampLinker sets the four linker-injected values for one test and
// restores the originals at cleanup. The linker seam is the package
// vars themselves (Makefile -ldflags -X).
func stampLinker(t *testing.T, v, c, d, f string) {
	t.Helper()
	oldVersion, oldCommit := version, commit
	oldDate, oldFlag := buildDate, dirtyFlag
	version, commit, buildDate, dirtyFlag = v, c, d, f
	t.Cleanup(func() {
		version, commit, buildDate, dirtyFlag = oldVersion, oldCommit, oldDate, oldFlag
	})
}

// TestForBuildsFromTheLinkerStamps: For names the program at compile
// time and carries the four linker-injected stamps onto the build
// value, which every accessor then serves.
func TestForBuildsFromTheLinkerStamps(t *testing.T) {
	stampLinker(t, "0.1.0", "abc1234", "2025-06-01T00:00:00Z", "false")

	b := For("bandage")
	if b.Name() != "bandage" {
		t.Errorf("Name() = %q, want %q", b.Name(), "bandage")
	}
	if b.Version() != "0.1.0" {
		t.Errorf("Version() = %q, want %q", b.Version(), "0.1.0")
	}
	if b.Commit() != "abc1234" {
		t.Errorf("Commit() = %q, want %q", b.Commit(), "abc1234")
	}
	if b.BuildDate() != "2025-06-01T00:00:00Z" {
		t.Errorf("BuildDate() = %q, want %q", b.BuildDate(), "2025-06-01T00:00:00Z")
	}
	if b.Dirty() {
		t.Error("Dirty() = true, want false")
	}
	if b.GoVersion() == "" {
		t.Error("GoVersion() is empty")
	}
	if b.Platform() == "" {
		t.Error("Platform() is empty")
	}
}

// TestForParsesTheDirtyFlag: the dirty stamp is a boolean flag string;
// anything unparseable reads as a clean tree.
func TestForParsesTheDirtyFlag(t *testing.T) {
	tests := []struct {
		name string
		flag string
		want bool
	}{
		{name: "dirty build", flag: "true", want: true},
		{name: "clean build", flag: "false", want: false},
		{name: "empty stamp", flag: "", want: false},
		{name: "unparseable stamp", flag: "garbage", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stampLinker(t, "0.1.0", "abc1234", "2025-06-01T00:00:00Z", tt.flag)
			if got := For("bandage").Dirty(); got != tt.want {
				t.Errorf("Dirty() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestForRendersEachProgramFromTheSameStamps: both commands draw one
// per-name build value from the same stamps; only the name differs.
func TestForRendersEachProgramFromTheSameStamps(t *testing.T) {
	stampLinker(t, "0.1.0", "abc1234", "2025-06-01T00:00:00Z", "false")

	if got := For("splint").String(); !strings.HasPrefix(got, "splint 0.1.0 abc1234 2025-06-01T00:00:00Z (") {
		t.Errorf("splint String() = %q, want the named stamped prefix", got)
	}
}

// stamped assembles a Build from release-like stamps. The rendering
// tests pin the exact operator-visible forms byte for byte; the
// environment-derived fields are fixed so the pin is total.
func stamped(name, version, commit, buildDate string, dirty bool) Build {
	return Build{
		name:      name,
		version:   version,
		commit:    commit,
		buildDate: buildDate,
		dirty:     dirty,
		goVersion: "go1.27.3",
		platform:  "linux/amd64",
	}
}

// TestBuildStringRendersTheSummary: the one-line summary (`-v`) keeps
// its exact form: "name version[ commit[-dirty]][ date] (go platform)".
func TestBuildStringRendersTheSummary(t *testing.T) {
	tests := []struct {
		name  string
		build Build
		want  string
	}{
		{
			name:  "release build",
			build: stamped("bandage", "0.1.0", "abc1234", "2025-06-01T00:00:00Z", false),
			want:  "bandage 0.1.0 abc1234 2025-06-01T00:00:00Z (go1.27.3 linux/amd64)",
		},
		{
			name:  "dirty build",
			build: stamped("bandage", "0.1.0", "abc1234", "2025-06-01T00:00:00Z", true),
			want:  "bandage 0.1.0 abc1234-dirty 2025-06-01T00:00:00Z (go1.27.3 linux/amd64)",
		},
		{
			name:  "commit without build date",
			build: stamped("bandage", "0.1.0", "abc1234", "", false),
			want:  "bandage 0.1.0 abc1234 (go1.27.3 linux/amd64)",
		},
		{
			name:  "unreleased build",
			build: stamped("bandage", "dev", "", "", false),
			want:  "bandage dev (go1.27.3 linux/amd64)",
		},
		{
			name:  "dirty without commit is not rendered",
			build: stamped("bandage", "dev", "", "", true),
			want:  "bandage dev (go1.27.3 linux/amd64)",
		},
		{
			name:  "second program name",
			build: stamped("splint", "0.1.0", "abc1234", "2025-06-01T00:00:00Z", false),
			want:  "splint 0.1.0 abc1234 2025-06-01T00:00:00Z (go1.27.3 linux/amd64)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.build.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildHeaderRendersTheShortIdentity: the short identity (`--test`
// plan banner) keeps its exact form: "name version[ (commit)]".
func TestBuildHeaderRendersTheShortIdentity(t *testing.T) {
	tests := []struct {
		name  string
		build Build
		want  string
	}{
		{
			name:  "release build",
			build: stamped("bandage", "0.1.0", "abc1234", "2025-06-01T00:00:00Z", false),
			want:  "bandage 0.1.0 (abc1234)",
		},
		{
			name:  "unreleased build",
			build: stamped("bandage", "dev", "", "", false),
			want:  "bandage dev",
		},
		{
			name:  "second program name",
			build: stamped("splint", "0.1.0", "abc1234", "2025-06-01T00:00:00Z", false),
			want:  "splint 0.1.0 (abc1234)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.build.Header(); got != tt.want {
				t.Errorf("Header() = %q, want %q", got, tt.want)
			}
		})
	}
}
