package pmgbot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ParserConfig struct {
	Before    time.Duration
	Blacklist string
	Exclude   string
	Timeout   time.Duration
}

type ImporterConfig struct {
	Blacklist string
	Exclude   string
	WhoName   string
	Timeout   time.Duration
}

type DaemonConfig struct {
	Before          time.Duration
	Every           time.Duration
	Exclude         string
	ParseTimeout    time.Duration
	ImporterWhoName string
	ImportTimeout   time.Duration
}

type FileConfig struct {
	LogLevel  string           `yaml:"log_level"`
	LogPath   string           `yaml:"log_path"`
	Sudo      bool             `yaml:"sudo"`
	Blacklist string           `yaml:"blacklist"`
	Exclude   string           `yaml:"exclude"`
	Daemon    FileDaemonConfig `yaml:"daemon"`
}

type FileDaemonConfig struct {
	Before          Duration `yaml:"before"`
	Every           Duration `yaml:"every"`
	ParseTimeout    Duration `yaml:"parse_timeout"`
	ImporterWhoName string   `yaml:"importer_who_name"`
	ImportTimeout   Duration `yaml:"import_timeout"`
}

type Duration time.Duration

func (duration Duration) MarshalYAML() (any, error) {
	return time.Duration(duration).String(), nil
}

func (duration *Duration) UnmarshalYAML(value *yaml.Node) error {
	parsed, err := parseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value.Value, err)
	}

	*duration = Duration(parsed)
	return nil
}

func (duration Duration) String() string {
	return time.Duration(duration).String()
}

func (duration *Duration) Set(value string) error {
	parsed, err := parseDuration(value)
	if err != nil {
		return err
	}

	*duration = Duration(parsed)
	return nil
}

func (duration Duration) Type() string {
	return "duration"
}

func parseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("duration is empty")
	}
	if isDigits(value) {
		value += "m"
	}

	return time.ParseDuration(value)
}

func isDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func LoadFileConfig(path string) (FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, fmt.Errorf("read config %s: %w", path, err)
	}

	var config FileConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return FileConfig{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	return config, nil
}

func SaveFileConfig(path string, config FileConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}

	return nil
}

func (config FileConfig) DaemonConfig() DaemonConfig {
	return DaemonConfig{
		Before:          time.Duration(config.Daemon.Before),
		Every:           time.Duration(config.Daemon.Every),
		Exclude:         config.Exclude,
		ParseTimeout:    time.Duration(config.Daemon.ParseTimeout),
		ImporterWhoName: config.Daemon.ImporterWhoName,
		ImportTimeout:   time.Duration(config.Daemon.ImportTimeout),
	}
}
