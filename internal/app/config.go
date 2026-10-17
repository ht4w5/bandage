// Package app wires the daemon: strict config and rules loading, the
// ingest → parse → evaluate → report pipeline, and the HTTP API server.
package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"gopkg.in/yaml.v3"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// DefaultCacheEntries is the default tracker cache entry cap.
const DefaultCacheEntries = 65536

// Config is the validated daemon configuration. It is decoded strictly:
// unknown keys and invalid values abort startup before any socket opens.
type Config struct {
	Ingest   Ingest
	DB       DB
	Cache    Cache
	Pipeline Pipeline
	API      API
	Log      Log
}

// Ingest configures the ingest driver and the log parser.
type Ingest struct {
	Driver string
	Parser string
	Syslog Syslog
}

// Syslog configures the syslog ingest listener.
type Syslog struct {
	Network string // tcp | udp | unixgram
	Listen  string
}

// DB configures the persistence driver.
type DB struct {
	Driver string
	SQLite SQLite
}

// SQLite configures the sqlite report store.
type SQLite struct {
	Path string
}

// Cache configures the tracker cache.
type Cache struct {
	MaxEntries int
}

// Pipeline configures the event-processing worker pool (ADR 0007).
// Workers is the resolved worker-goroutine count: always at least 1
// (validated at load).
type Pipeline struct {
	Workers int
}

// API configures the HTTP report API listener.
type API struct {
	Listen string
}

// Log configures the program-wide logger (ADR 0005). Level is the
// four-word vocabulary; the rendering is fixed console-style text on
// stderr.
type Log struct {
	Level bandage.Level
}

// raw config wire types (strict decode).

type rawConfig struct {
	Ingest   rawIngest   `yaml:"ingest"`
	DB       rawDB       `yaml:"db"`
	Cache    rawCache    `yaml:"cache"`
	Pipeline rawPipeline `yaml:"pipeline"`
	API      rawAPI      `yaml:"api"`
	Log      rawLog      `yaml:"log"`
}

type rawIngest struct {
	Driver string    `yaml:"driver"`
	Syslog rawSyslog `yaml:"syslog"`
	Parser string    `yaml:"parser"`
}

type rawSyslog struct {
	Network string `yaml:"network"`
	Listen  string `yaml:"listen"`
}

type rawDB struct {
	Driver string    `yaml:"driver"`
	SQLite rawSQLite `yaml:"sqlite"`
}

type rawSQLite struct {
	Path string `yaml:"path"`
}

type rawCache struct {
	MaxEntries *int `yaml:"max_entries"`
}

type rawPipeline struct {
	Workers *int `yaml:"workers"`
}

type rawAPI struct {
	Listen string `yaml:"listen"`
}

type rawLog struct {
	Level string `yaml:"level"`
}

// LoadConfig reads and validates the config file at path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// ParseConfig strictly decodes and validates a config document. Unknown
// keys and invalid values are errors.
func ParseConfig(data []byte) (Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("config: empty document")
		}
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return Config{}, errors.New("config: multiple YAML documents")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}
	return validateConfig(raw)
}

func validateConfig(raw rawConfig) (Config, error) {
	cfg := Config{
		Ingest: Ingest{
			Driver: raw.Ingest.Driver,
			Parser: raw.Ingest.Parser,
			Syslog: Syslog{Network: raw.Ingest.Syslog.Network, Listen: raw.Ingest.Syslog.Listen},
		},
		DB:    DB{Driver: raw.DB.Driver, SQLite: SQLite{Path: raw.DB.SQLite.Path}},
		API:   API{Listen: raw.API.Listen},
		Cache: Cache{MaxEntries: DefaultCacheEntries},
		Log:   Log{Level: bandage.LevelInfo},
		// pipeline.workers defaults to the machine's CPU count (spec
		// story 15).
		Pipeline: Pipeline{Workers: runtime.NumCPU()},
	}

	switch {
	case cfg.Ingest.Driver == "":
		return Config{}, errors.New(`config: ingest.driver: required, want "syslog"`)
	case cfg.Ingest.Driver != "syslog":
		return Config{}, fmt.Errorf(`config: ingest.driver: unknown ingest driver %q (want "syslog")`, cfg.Ingest.Driver)
	}
	switch {
	case cfg.Ingest.Parser == "":
		return Config{}, errors.New(`config: ingest.parser: required, want "nginx"`)
	case cfg.Ingest.Parser != "nginx":
		return Config{}, fmt.Errorf(`config: ingest.parser: unknown ingest parser %q (want "nginx")`, cfg.Ingest.Parser)
	}
	switch cfg.Ingest.Syslog.Network {
	case "":
		return Config{}, errors.New(`config: ingest.syslog.network: required, want "tcp", "udp" or "unixgram"`)
	case "tcp", "udp", "unixgram":
	default:
		return Config{}, fmt.Errorf(`config: ingest.syslog.network: unknown network %q (want "tcp", "udp" or "unixgram")`, cfg.Ingest.Syslog.Network)
	}
	if cfg.Ingest.Syslog.Listen == "" {
		return Config{}, errors.New("config: ingest.syslog.listen: required")
	}
	switch {
	case cfg.DB.Driver == "":
		return Config{}, errors.New(`config: db.driver: required, want "sqlite"`)
	case cfg.DB.Driver != "sqlite":
		return Config{}, fmt.Errorf(`config: db.driver: unknown db driver %q (want "sqlite")`, cfg.DB.Driver)
	}
	if cfg.DB.SQLite.Path == "" {
		return Config{}, errors.New("config: db.sqlite.path: required")
	}
	if raw.Cache.MaxEntries != nil {
		if *raw.Cache.MaxEntries <= 0 {
			return Config{}, errors.New("config: cache.max_entries: must be positive")
		}
		cfg.Cache.MaxEntries = *raw.Cache.MaxEntries
	}
	if raw.Pipeline.Workers != nil {
		if *raw.Pipeline.Workers < 1 {
			return Config{}, errors.New("config: pipeline.workers: must be positive")
		}
		cfg.Pipeline.Workers = *raw.Pipeline.Workers
	}
	if cfg.API.Listen == "" {
		return Config{}, errors.New("config: api.listen: required")
	}
	if raw.Log.Level != "" {
		// log.level shares the one level parser with the log action: the
		// same four words, so both always mean the same thing.
		level, err := bandage.ParseLevel(raw.Log.Level)
		if err != nil {
			return Config{}, fmt.Errorf("config: log.level: %w", err)
		}
		cfg.Log.Level = level
	}
	return cfg, nil
}
