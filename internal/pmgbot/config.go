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
	Rules   Rules
}

type FileConfig struct {
	LogLevel string           `yaml:"log_level"`
	LogPath  string           `yaml:"log_path"`
	Sudo     bool             `yaml:"sudo"`
	Daemon   FileDaemonConfig `yaml:"daemon"`
	Rules    Rules            `yaml:"rules"`
}

type FileDaemonConfig struct {
	Every   Duration `yaml:"every"`
	Timeout Duration `yaml:"timeout"`
}

type FieldPatterns map[string][]string

type Rules []Rule

type Rule struct {
	Name   string           `yaml:"name"`
	Action quarantineAction `yaml:"action"`
	When   RuleGroups       `yaml:"when"`
}

type RuleGroups []FieldPatterns

func (groups RuleGroups) MarshalYAML() (any, error) {
	return []FieldPatterns(groups), nil
}

func (groups *RuleGroups) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		return groups.unmarshalRuleList(value)
	case yaml.ScalarNode:
		if strings.TrimSpace(value.Value) == "" {
			*groups = nil
			return nil
		}
	}

	return fmt.Errorf("rules must be a rule list")
}

func (groups *RuleGroups) unmarshalRuleList(value *yaml.Node) error {
	var loaded RuleGroups
	for _, item := range value.Content {
		if item.Kind != yaml.MappingNode {
			return fmt.Errorf("rule must be a field map")
		}

		rule := make(FieldPatterns)
		for i := 0; i < len(item.Content); i += 2 {
			field := strings.TrimSpace(item.Content[i].Value)
			patterns, err := decodePatternList(item.Content[i+1])
			if err != nil {
				return fmt.Errorf("decode patterns for field %q: %w", field, err)
			}
			if field == "" || !hasFieldPatterns(patterns) {
				continue
			}

			rule[field] = patterns
		}
		if len(rule) == 0 {
			continue
		}

		loaded = append(loaded, rule)
	}

	*groups = loaded
	return nil
}

func decodePatternList(value *yaml.Node) ([]string, error) {
	switch value.Kind {
	case yaml.ScalarNode:
		return []string{value.Value}, nil
	case yaml.SequenceNode:
		patterns := make([]string, 0, len(value.Content))
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("pattern must be a string")
			}
			patterns = append(patterns, item.Value)
		}

		return patterns, nil
	default:
		return nil, fmt.Errorf("patterns must be a string or string list")
	}
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
		Every:   time.Duration(config.Daemon.Every),
		Timeout: time.Duration(config.Daemon.Timeout),
		Rules:   config.Rules,
	}
}
