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
		Deliver: FieldPatterns{
			"envelope_sender": {`^trusted@example\.com$`},
			"subject":         {`(?i)important`},
		},
		Delete: FieldPatterns{
			"envelope_sender": {`@bad\.ru$`},
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
	if loaded.Deliver["envelope_sender"][0] != `^trusted@example\.com$` {
		t.Fatalf("got deliver patterns %#v", loaded.Deliver)
	}
	if loaded.Delete["envelope_sender"][0] != `@bad\.ru$` {
		t.Fatalf("got delete patterns %#v", loaded.Delete)
	}
	if loaded.DaemonConfig().Deliver["subject"][0] != `(?i)important` {
		t.Fatalf("got daemon deliver patterns %#v", loaded.DaemonConfig().Deliver)
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
		`deliver: {}`,
		`delete: {}`,
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
		`deliver: {}`,
		`delete: {}`,
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
