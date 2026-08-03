package pmgbot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type DaemonConfig struct {
	Every   time.Duration
	Timeout time.Duration
	Deliver FieldPatterns
	Delete  FieldPatterns
}

type FileConfig struct {
	LogLevel string           `yaml:"log_level"`
	LogPath  string           `yaml:"log_path"`
	Sudo     bool             `yaml:"sudo"`
	Daemon   FileDaemonConfig `yaml:"daemon"`
	Deliver  FieldPatterns    `yaml:"deliver"`
	Delete   FieldPatterns    `yaml:"delete"`
}

type FileDaemonConfig struct {
	Every   Duration `yaml:"every"`
	Timeout Duration `yaml:"timeout"`
}

type FieldPatterns map[string][]string

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
		Every:   time.Duration(config.Daemon.Every),
		Timeout: time.Duration(config.Daemon.Timeout),
		Deliver: config.Deliver,
		Delete:  config.Delete,
	}
}
