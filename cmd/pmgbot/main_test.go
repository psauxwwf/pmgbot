package main

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"pmgbot/internal/pmgbot"
)

func TestRootCommandsAndFlags(t *testing.T) {
	root := rootCmd()

	for _, name := range []string{"parse", "import"} {
		if commandExists(root, name) {
			t.Fatalf("obsolete command %q found", name)
		}
	}

	daemon, _, err := root.Find([]string{"daemon"})
	if err != nil {
		t.Fatal(err)
	}
	if daemon == nil {
		t.Fatal("daemon command not found")
	}
	for _, name := range []string{"before", "since", "timeout", "cmd-timeout", "name"} {
		if daemon.Flags().Lookup(name) != nil {
			t.Fatalf("yaml-only daemon flag %q found", name)
		}
	}
	for _, name := range []string{"blacklist", "exclude", "log-level", "log-path", "sudo"} {
		if root.PersistentFlags().Lookup(name) != nil {
			t.Fatalf("obsolete persistent flag %q found", name)
		}
	}

	for _, name := range []string{"config", "save-config"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Fatalf("config flag %q not found", name)
		}
	}
}

func TestConfigDefaultPath(t *testing.T) {
	root := rootCmd()

	flag := root.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("config flag not found")
	}
	if flag.DefValue != defaultConfigPath {
		t.Fatalf("got %q, want %q", flag.DefValue, defaultConfigPath)
	}
}

func TestConfigDefault(t *testing.T) {
	config := defaultFileConfig(time.Date(2026, 7, 29, 15, 55, 0, 0, time.UTC))

	if config.LogLevel != defaultLogLevel {
		t.Fatalf("got log level %q, want %q", config.LogLevel, defaultLogLevel)
	}
	if !config.Sudo {
		t.Fatal("default config sudo must be enabled")
	}
	if time.Duration(config.Daemon.Every) != defaultDaemonEvery {
		t.Fatalf("got daemon every %s, want %s", time.Duration(config.Daemon.Every), defaultDaemonEvery)
	}
	if time.Duration(config.Daemon.Timeout) != defaultDaemonTimeout {
		t.Fatalf("got daemon timeout %s, want %s", time.Duration(config.Daemon.Timeout), defaultDaemonTimeout)
	}
	if config.Deliver["envelope_sender"][0] != `^trusted@example\.com$` {
		t.Fatalf("got deliver patterns %#v", config.Deliver)
	}
	if config.Deliver["receiver"][0] != `^vip@example\.com$` {
		t.Fatalf("got deliver patterns %#v", config.Deliver)
	}
	if config.Delete["envelope_sender"][1] != `^[^@]+@([^.@]+\.)*sendsay\.ru$` {
		t.Fatalf("got delete patterns %#v", config.Delete)
	}
	for _, field := range []string{"bytes", "id", "spamlevel", "time"} {
		if _, ok := config.Deliver[field]; ok {
			t.Fatalf("unexpected deliver field %q in default config", field)
		}
		if _, ok := config.Delete[field]; ok {
			t.Fatalf("unexpected delete field %q in default config", field)
		}
	}
}

func TestRootWithoutSubcommandRunsOneCycle(t *testing.T) {
	originalRunOnce := runOnce
	t.Cleanup(func() { runOnce = originalRunOnce })

	var called bool
	runOnce = func(_ context.Context, config pmgbot.DaemonConfig) error {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		return nil
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	root := rootCmd()
	root.SetArgs([]string{"--config", configPath})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected root command to run one cycle")
	}
}

func commandExists(root *cobra.Command, name string) bool {
	cmd, _, err := root.Find([]string{name})
	return err == nil && cmd != nil && cmd.Name() == name
}
