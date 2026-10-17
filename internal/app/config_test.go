package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// The config surface (PLAN §3) is strictly decoded before any socket
// opens: unknown keys and invalid values abort startup.
const validConfig = `
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

func TestParseConfigValid(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}
	if cfg.Ingest.Driver != "syslog" || cfg.Ingest.Parser != "nginx" {
		t.Errorf("ingest = %+v, want driver syslog, parser nginx", cfg.Ingest)
	}
	if cfg.Ingest.Syslog.Network != "unixgram" || cfg.Ingest.Syslog.Listen != "/run/bandage/log.sock" {
		t.Errorf("syslog = %+v, want unixgram /run/bandage/log.sock", cfg.Ingest.Syslog)
	}
	if cfg.DB.Driver != "sqlite" || cfg.DB.SQLite.Path != "/var/lib/bandage/reports.db" {
		t.Errorf("db = %+v, want sqlite /var/lib/bandage/reports.db", cfg.DB)
	}
	if cfg.Cache.MaxEntries != 65536 {
		t.Errorf("cache.max_entries = %d, want 65536", cfg.Cache.MaxEntries)
	}
	if cfg.API.Listen != "127.0.0.1:8080" {
		t.Errorf("api.listen = %q, want 127.0.0.1:8080", cfg.API.Listen)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
ingest:
  driver: syslog
  syslog: {network: tcp, listen: "0.0.0.0:514"}
  parser: nginx
db:
  driver: sqlite
  sqlite: {path: reports.db}
api: {listen: "127.0.0.1:8080"}
`))
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}
	if cfg.Cache.MaxEntries != 65536 {
		t.Errorf("cache.max_entries = %d, want default 65536", cfg.Cache.MaxEntries)
	}
	if cfg.Log.Level != bandage.LevelInfo {
		t.Errorf("log.level = %q, want default %q", cfg.Log.Level, bandage.LevelInfo)
	}
}

// log.level accepts exactly the four level words (default info), shared
// with the one level parser; the strict load rejects any other value
// before any socket opens (spec: Config surface; stories 10, 13).
func TestParseConfigLogLevel(t *testing.T) {
	valid := strings.Replace(validConfig, "api:", "log:\n  level: %s\n\napi:", 1)
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			cfg, err := ParseConfig([]byte(strings.Replace(valid, "%s", level, 1)))
			if err != nil {
				t.Fatalf("ParseConfig error: %v", err)
			}
			if cfg.Log.Level != bandage.Level(level) {
				t.Errorf("log.level = %q, want %q", cfg.Log.Level, level)
			}
		})
	}
	for _, level := range []string{"trace", "fatal", "panic", "warning", "INFO2"} {
		t.Run("rejects "+level, func(t *testing.T) {
			_, err := ParseConfig([]byte(strings.Replace(valid, "%s", level, 1)))
			if err == nil {
				t.Fatalf("ParseConfig succeeded, want %q rejected", level)
			}
			if !strings.Contains(err.Error(), "log.level") {
				t.Errorf("error %q does not contain %q", err, "log.level")
			}
		})
	}
}

func TestParseConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "unknown top-level key", yaml: validConfig + "\nbogus: true\n", wantErr: "bogus"},
		{name: "unknown ingest key", yaml: strings.Replace(validConfig, "  parser: nginx", "  parsers: nginx", 1), wantErr: "parsers"},
		{name: "unknown syslog key", yaml: strings.Replace(validConfig, "    listen: /run/bandage/log.sock", "    listen: /run/bandage/log.sock\n    sock: x", 1), wantErr: "sock"},
		{name: "unknown db key", yaml: strings.Replace(validConfig, "    path: /var/lib/bandage/reports.db", "    path: /var/lib/bandage/reports.db\n    extra: x", 1), wantErr: "extra"},
		{name: "unknown cache key", yaml: strings.Replace(validConfig, "  max_entries: 65536", "  max_entries: 65536\n  shards: 8", 1), wantErr: "shards"},
		{name: "unknown api key", yaml: strings.Replace(validConfig, "  listen: 127.0.0.1:8080", "  listen: 127.0.0.1:8080\n  metrics: true", 1), wantErr: "metrics"},
		{name: "unknown log key", yaml: strings.Replace(validConfig, "api:", "log:\n  verbosity: 1\n\napi:", 1), wantErr: "verbosity"},
		{name: "missing ingest driver", yaml: strings.Replace(validConfig, "  driver: syslog\n", "", 1), wantErr: "ingest.driver"},
		{name: "unknown ingest driver", yaml: strings.Replace(validConfig, "driver: syslog", "driver: kafka", 1), wantErr: "ingest driver"},
		{name: "missing parser", yaml: strings.Replace(validConfig, "  parser: nginx\n", "", 1), wantErr: "ingest.parser"},
		{name: "unknown parser", yaml: strings.Replace(validConfig, "parser: nginx", "parser: csv", 1), wantErr: "ingest parser"},
		{name: "missing network", yaml: strings.Replace(validConfig, "    network: unixgram\n", "", 1), wantErr: "network"},
		{name: "unknown network", yaml: strings.Replace(validConfig, "network: unixgram", "network: unix", 1), wantErr: "network"},
		{name: "missing listen", yaml: strings.Replace(validConfig, "    listen: /run/bandage/log.sock\n", "", 1), wantErr: "listen"},
		{name: "empty listen", yaml: strings.Replace(validConfig, "listen: /run/bandage/log.sock", `listen: ""`, 1), wantErr: "listen"},
		{name: "missing db driver", yaml: strings.Replace(validConfig, "  driver: sqlite\n", "", 1), wantErr: "db.driver"},
		{name: "unknown db driver", yaml: strings.Replace(validConfig, "driver: sqlite", "driver: postgres", 1), wantErr: "db driver"},
		{name: "missing db path", yaml: strings.Replace(validConfig, "    path: /var/lib/bandage/reports.db\n", "", 1), wantErr: "path"},
		{name: "empty db path", yaml: strings.Replace(validConfig, "path: /var/lib/bandage/reports.db", `path: ""`, 1), wantErr: "path"},
		{name: "zero cache entries", yaml: strings.Replace(validConfig, "max_entries: 65536", "max_entries: 0", 1), wantErr: "max_entries"},
		{name: "negative cache entries", yaml: strings.Replace(validConfig, "max_entries: 65536", "max_entries: -1", 1), wantErr: "max_entries"},
		{name: "missing api listen", yaml: strings.Replace(validConfig, "  listen: 127.0.0.1:8080\n", "", 1), wantErr: "api.listen"},
		{name: "empty api listen", yaml: strings.Replace(validConfig, "listen: 127.0.0.1:8080", `listen: ""`, 1), wantErr: "api.listen"},
		{name: "multiple documents", yaml: validConfig + "\n---\ningest: {}\n", wantErr: "document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("ParseConfig succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bandage.yml")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.API.Listen != "127.0.0.1:8080" {
		t.Errorf("api.listen = %q", cfg.API.Listen)
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yml")); err == nil {
		t.Error("LoadConfig(missing) succeeded, want error")
	}
}
