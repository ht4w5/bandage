package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HT4w5/bandage/internal/identity"
)

// Flag parsing, shorthands, exit behavior and flag > config > default
// precedence live behind the run(args) seam (spec Testing Decisions:
// the one new seam — nothing else may be tested through it; the plan
// text itself is asserted at the app seam, the --test plan tests).

const testConfig = `
ingest:
  driver: syslog
  syslog:
    network: unixgram
    listen: /run/bandage/log.sock
  parser: nginx

db:
  driver: sqlite
  sqlite:
    path: /var/lib/bandage/reports.db

cache:
  max_entries: 65536

api:
  listen: 127.0.0.1:8080
`

const testRules = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: sustained-egress
        tracker:
          track: bandwidth
          leak: 1000
          volume: 10000
        actions:
          - report:
              reason: egress-overflow
              ttl: 24h
`

// writeConfig writes valid config and rules files and returns their
// paths.
func writeConfig(t *testing.T) (cfgPath, rulesPath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "bandage.yml")
	rulesPath = filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(cfgPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, rulesPath
}

func TestVersionFlagPrintsIdentity(t *testing.T) {
	for _, args := range [][]string{{"-v"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		code, _ := run(args, &stdout, &stderr)
		if code != 0 {
			t.Errorf("run(%v) code = %d, want 0 (stderr %q)", args, code, stderr.String())
		}
		// The identity summary carries name, version, Go version and
		// platform; commit and build date are empty in a dev build.
		for _, want := range []string{
			identity.Name,
			identity.Version(),
			identity.GoVersion(),
			identity.Platform(),
		} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("run(%v) stdout = %q, want it to contain %q", args, stdout.String(), want)
			}
		}
	}
}

func TestHelpFlagPrintsUsage(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		var stdout, stderr bytes.Buffer
		code, _ := run(args, &stdout, &stderr)
		if code != 0 {
			t.Errorf("run(%v) code = %d, want 0 (stderr %q)", args, code, stderr.String())
		}
		// Usage is headed by the short identity (name, version, commit)
		// and lists every flag with its shorthand.
		if !strings.HasPrefix(stdout.String(), identity.Header()) {
			t.Errorf("run(%v) stdout = %q, want it headed by the identity header %q",
				args, stdout.String(), identity.Header())
		}
		for _, want := range []string{
			"Usage:",
			"-c, --config",
			"-r, --rules",
			"-t, --test",
			"-l, --log-level",
			"-w, --workers",
			"-v, --version",
			"-h, --help",
		} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("run(%v) stdout = %q, want it to contain %q", args, stdout.String(), want)
			}
		}
	}
}

func TestUnknownFlagExitsTwoWithUsage(t *testing.T) {
	tests := []struct {
		args    []string
		wantErr string
	}{
		{args: []string{"--bogus"}, wantErr: "unknown flag: --bogus"},
		{args: []string{"-z"}, wantErr: "unknown shorthand flag: 'z'"},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code, _ := run(tt.args, &stdout, &stderr)
		if code != 2 {
			t.Errorf("run(%v) code = %d, want 2", tt.args, code)
		}
		if !strings.Contains(stderr.String(), tt.wantErr) {
			t.Errorf("run(%v) stderr = %q, want it to contain %q", tt.args, stderr.String(), tt.wantErr)
		}
		if !strings.Contains(stderr.String(), "Usage:") {
			t.Errorf("run(%v) stderr = %q, want it to contain the usage", tt.args, stderr.String())
		}
	}
}

func TestTestModeShorthandsMatchLongForms(t *testing.T) {
	cfgPath, rulesPath := writeConfig(t)
	base := []string{"--config", cfgPath, "--rules", rulesPath}

	var longOut, longErr bytes.Buffer
	longCode, _ := run(append([]string{"--test"}, base...), &longOut, &longErr)
	var shortOut, shortErr bytes.Buffer
	shortCode, _ := run([]string{"-t", "-c", cfgPath, "-r", rulesPath}, &shortOut, &shortErr)

	if longCode != 0 || shortCode != 0 {
		t.Fatalf("codes = %d (long) / %d (short), want 0/0 (stderr %q / %q)",
			longCode, shortCode, longErr.String(), shortErr.String())
	}
	if longOut.String() != shortOut.String() {
		t.Errorf("short plan output\n%q\n!= long form\n%q", shortOut.String(), longOut.String())
	}
	// The plan output opens with the build identity header (spec story
	// 6); its contents are asserted at the app seam.
	if !strings.HasPrefix(longOut.String(), identity.Header()+"\n") {
		t.Errorf("plan = %q, want it to open with the identity header %q", longOut.String(), identity.Header())
	}
}

func TestTestModeFailsNonZeroOnInvalidInput(t *testing.T) {
	cfgPath, rulesPath := writeConfig(t)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing config",
			args:    []string{"-t", "-c", filepath.Join(t.TempDir(), "nope.yml"), "-r", rulesPath},
			wantErr: "nope.yml",
		},
		{
			name:    "invalid config",
			args:    []string{"-t", "-c", writeTemp(t, "bogus: true\n"), "-r", rulesPath},
			wantErr: "bogus",
		},
		{
			name:    "invalid rules",
			args:    []string{"-t", "-c", cfgPath, "-r", writeTemp(t, "version: 1\n")},
			wantErr: "version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code, _ := run(tt.args, &stdout, &stderr)
			if code != 1 {
				t.Errorf("code = %d, want 1 (stdout %q)", code, stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain the load error %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestLogLevelPrecedence(t *testing.T) {
	cfgPath, rulesPath := writeConfig(t)

	// Flag > config > default: the explicit -l wins, then log.level,
	// then the built-in default (spec: precedence).
	tests := []struct {
		name   string
		config string // empty: the default valid fixture
		extra  []string
		want   string
	}{
		{name: "default", want: "info"},
		{name: "config over default", config: testConfig + "\nlog:\n  level: warn\n", want: "warn"},
		{name: "flag over config", config: testConfig + "\nlog:\n  level: warn\n", extra: []string{"-l", "error"}, want: "error"},
		{name: "short flag", extra: []string{"-l", "warn"}, want: "warn"},
		{name: "long flag", extra: []string{"--log-level", "debug"}, want: "debug"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := cfgPath
			if tt.config != "" {
				cfg = writeTemp(t, tt.config)
			}
			args := []string{"-t", "-c", cfg, "-r", rulesPath}
			var stdout, stderr bytes.Buffer
			code, opts := run(append(args, tt.extra...), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code = %d, want 0 (stderr %q)", code, stderr.String())
			}
			if opts.logLevel != tt.want {
				t.Errorf("logLevel = %q, want %q (flag > config > default)", opts.logLevel, tt.want)
			}
		})
	}
}

func TestWorkersPrecedence(t *testing.T) {
	cfgPath, rulesPath := writeConfig(t)
	base := []string{"-t", "-c", cfgPath, "-r", rulesPath}

	tests := []struct {
		name  string
		extra []string
		want  int
	}{
		{name: "default", want: 0},
		{name: "short flag", extra: []string{"-w", "4"}, want: 4},
		{name: "long flag", extra: []string{"--workers", "8"}, want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code, opts := run(append(append([]string{}, base...), tt.extra...), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code = %d, want 0 (stderr %q)", code, stderr.String())
			}
			if opts.workers != tt.want {
				t.Errorf("workers = %d, want %d (flag > config > default)", opts.workers, tt.want)
			}
		})
	}
}

func TestInvalidLogLevelFails(t *testing.T) {
	cfgPath, rulesPath := writeConfig(t)
	var stdout, stderr bytes.Buffer
	code, _ := run([]string{"-t", "-c", cfgPath, "-r", rulesPath, "-l", "bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown log level") {
		t.Errorf("stderr = %q, want the level error", stderr.String())
	}
}

// writeTemp writes content to a named temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
