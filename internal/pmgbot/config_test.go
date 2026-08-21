package pmgbot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	config := FileConfig{
		LogLevel: "debug",
		LogPath:  "pmgbot.log",
		Sudo:     true,
		Daemon: FileDaemonConfig{
			Every:   Duration(15 * time.Minute),
			Timeout: Duration(2 * time.Minute),
		},
		Rules: Rules{
			{
				Name:   "Deliver trusted",
				Action: quarantineActionDeliver,
				When: RuleGroups{
					{"envelope_sender": {`^trusted@example\.com$`}},
					{"subject": {`(?i)important`}},
				},
			},
			{
				Name:   "Delete bad",
				Action: quarantineActionDelete,
				When: RuleGroups{
					{"envelope_sender": {`@bad\.ru$`}},
				},
			},
		},
	}

	if err := SaveFileConfig(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.LogLevel != config.LogLevel {
		t.Fatalf("got log level %q, want %q", loaded.LogLevel, config.LogLevel)
	}
	if time.Duration(loaded.Daemon.Every) != 15*time.Minute {
		t.Fatalf("got daemon every %s, want 15m", time.Duration(loaded.Daemon.Every))
	}
	if time.Duration(loaded.Daemon.Timeout) != 2*time.Minute {
		t.Fatalf("got daemon timeout %s, want 2m", time.Duration(loaded.Daemon.Timeout))
	}
	if loaded.Rules[0].Name != "Deliver trusted" || loaded.Rules[0].Action != quarantineActionDeliver {
		t.Fatalf("got rules %#v", loaded.Rules)
	}
	if loaded.Rules[0].When[0]["envelope_sender"][0] != `^trusted@example\.com$` {
		t.Fatalf("got rules %#v", loaded.Rules)
	}
	if loaded.Rules[1].When[0]["envelope_sender"][0] != `@bad\.ru$` {
		t.Fatalf("got rules %#v", loaded.Rules)
	}
	if loaded.DaemonConfig().Rules[0].When[1]["subject"][0] != `(?i)important` {
		t.Fatalf("got daemon rules %#v", loaded.DaemonConfig().Rules)
	}
}

func TestFileConfigRejectsRuleWhenMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	content := strings.Join([]string{
		`log_level: info`,
		`log_path: ""`,
		`sudo: true`,
		`daemon:`,
		`  every: 15m`,
		`  timeout: 1m`,
		`rules:`,
		`  - name: Delete bad`,
		`    action: delete`,
		`    when:`,
		`      envelope_sender:`,
		`        - '@bad\.ru$'`,
		`      subject: '(?i)casino'`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFileConfig(path)
	if err == nil {
		t.Fatal("expected rule map error")
	}
	if !strings.Contains(err.Error(), "rules must be a rule list") {
		t.Fatalf("got error %q", err)
	}
}

func TestFileConfigLoadsRulesWithAndFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	content := strings.Join([]string{
		`log_level: info`,
		`log_path: ""`,
		`sudo: true`,
		`daemon:`,
		`  every: 15m`,
		`  timeout: 1m`,
		`rules:`,
		`  - name: Delete webmaster registration`,
		`    action: delete`,
		`    when:`,
		`      - envelope_sender: '^webmaster@rc\.ffff\.ru$'`,
		`        subject:`,
		`          - '^\[SPAM\]: Зарегистрировался новый пользователь$'`,
		`          - '^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$'`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Rules) != 1 {
		t.Fatalf("got rules %#v, want 1 rule", config.Rules)
	}
	if config.Rules[0].Action != quarantineActionDelete {
		t.Fatalf("got rules %#v", config.Rules)
	}
	if config.Rules[0].When[0]["envelope_sender"][0] != `^webmaster@rc\.ffff\.ru$` {
		t.Fatalf("got rules %#v", config.Rules)
	}
	if config.Rules[0].When[0]["subject"][1] != `^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$` {
		t.Fatalf("got rules %#v", config.Rules)
	}
}

func TestFileConfigLoadsRuleCountCondition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	content := strings.Join([]string{
		`log_level: info`,
		`log_path: ""`,
		`sudo: true`,
		`daemon:`,
		`  every: 15m`,
		`  timeout: 1m`,
		`rules:`,
		`  - name: Delete repeated subject`,
		`    action: delete`,
		`    when:`,
		`      - subject: '^TEST$'`,
		`        count: 3`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Rules[0].When[0]["count"][0] != "3" {
		t.Fatalf("got rules %#v", config.Rules)
	}
}

func TestFileConfigLoadsAndSavesRuleCountOperator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	config := FileConfig{
		LogLevel: "info",
		Sudo:     true,
		Daemon: FileDaemonConfig{
			Every:   Duration(15 * time.Minute),
			Timeout: Duration(time.Minute),
		},
		Rules: Rules{{
			Name:   "Delete more than three",
			Action: quarantineActionDelete,
			When:   RuleGroups{{"subject": {`^TEST$`}, "count": {">3"}}},
		}},
	}
	if err := SaveFileConfig(path, config); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "count: '>3'") {
		t.Fatalf("saved config %q does not contain scalar count", string(data))
	}

	loaded, err := LoadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Rules[0].When[0]["count"][0] != ">3" {
		t.Fatalf("got rules %#v", loaded.Rules)
	}
}

func TestDurationUnmarshalError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	content := strings.Join([]string{
		`log_level: info`,
		`log_path: ""`,
		`sudo: true`,
		`daemon:`,
		`  every: 15m`,
		`  timeout: nope`,
		`rules: []`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFileConfig(path)
	if err == nil {
		t.Fatal("expected duration parse error")
	}
}

func TestDurationSetUsesMinutesForBareNumber(t *testing.T) {
	var duration Duration
	if err := duration.Set("30"); err != nil {
		t.Fatal(err)
	}
	if time.Duration(duration) != 30*time.Minute {
		t.Fatalf("got %s, want 30m", time.Duration(duration))
	}
}

func TestDurationUnmarshalUsesMinutesForBareNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pmgbot.yaml")
	content := strings.Join([]string{
		`log_level: info`,
		`log_path: ""`,
		`sudo: true`,
		`daemon:`,
		`  every: 15`,
		`  timeout: 1m`,
		`rules: []`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(config.Daemon.Every) != 15*time.Minute {
		t.Fatalf("got daemon every %s, want 15m", time.Duration(config.Daemon.Every))
	}
}
