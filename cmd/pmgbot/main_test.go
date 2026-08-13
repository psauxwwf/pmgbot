package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
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

	for _, name := range []string{"run", "check", "analyze", "generate", "daemon"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if cmd == nil {
			t.Fatalf("%s command not found", name)
		}
	}
	daemon, _, err := root.Find([]string{"daemon"})
	if err != nil {
		t.Fatal(err)
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

	if root.PersistentFlags().Lookup("config") == nil {
		t.Fatal("config flag not found")
	}
	if root.PersistentFlags().Lookup("save-config") != nil {
		t.Fatal("save-config must not be a persistent flag")
	}
	if root.Flags().Lookup("save-config") == nil {
		t.Fatal("save-config root flag not found")
	}
	for _, name := range []string{"run", "check", "analyze", "generate", "daemon"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Flag("save-config") != nil {
			t.Fatalf("save-config must not be available for %s", name)
		}
	}
	for _, name := range []string{"config"} {
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

func TestDefaultExistingConfigPath(t *testing.T) {
	t.Chdir(t.TempDir())

	if got := defaultExistingConfigPath(); got != defaultConfigPath {
		t.Fatalf("got %q, want %q", got, defaultConfigPath)
	}

	if err := os.WriteFile(overrideConfigPath, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := defaultExistingConfigPath(); got != overrideConfigPath {
		t.Fatalf("got %q, want %q", got, overrideConfigPath)
	}

	if err := os.WriteFile(defaultConfigPath, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := defaultExistingConfigPath(); got != defaultConfigPath {
		t.Fatalf("got %q, want %q", got, defaultConfigPath)
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
	if len(config.Rules) != 15 {
		t.Fatalf("got %d rules, want 15", len(config.Rules))
	}
	if config.Rules[0].Name != "Delete webmaster registrations" || config.Rules[0].Action != "delete" {
		t.Fatalf("got rules %#v", config.Rules)
	}
	if config.Rules[0].When[0]["subject"][0] != `^\[SPAM\]: Зарегистрировался новый пользователь$` {
		t.Fatalf("got rules %#v", config.Rules)
	}
	if config.Rules[5].Name != "Delete webmaster registration or payment confirmations" || config.Rules[5].When[0]["subject"][1] != `^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$` {
		t.Fatalf("got rules %#v", config.Rules)
	}
	if config.Rules[14].Name != "Delete mixed phishing campaign" || len(config.Rules[14].When) != 2 {
		t.Fatalf("got rules %#v", config.Rules)
	}
	for _, field := range []string{"bytes", "id", "spamlevel", "time"} {
		for _, rule := range config.Rules {
			for _, group := range rule.When {
				if _, ok := group[field]; ok {
					t.Fatalf("unexpected field %q in default config", field)
				}
			}
		}
	}
}

func TestRootWithoutSubcommandDoesNotRunOneCycle(t *testing.T) {
	originalRunOnce := runOnce
	t.Cleanup(func() { runOnce = originalRunOnce })

	runOnce = func(_ context.Context, config pmgbot.DaemonConfig) error {
		t.Fatalf("root command must not run one cycle, got config %#v", config)
		return nil
	}

	root := rootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunCommandRunsOneCycle(t *testing.T) {
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
	root.SetArgs([]string{"--config", configPath, "run"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected run command to run one cycle")
	}
}

func TestRunCommandUsesOverrideConfigWhenDefaultMissing(t *testing.T) {
	originalRunOnce := runOnce
	t.Cleanup(func() { runOnce = originalRunOnce })
	t.Chdir(t.TempDir())

	config := defaultFileConfig(time.Now())
	config.Daemon.Timeout = pmgbot.Duration(7 * time.Minute)
	if err := pmgbot.SaveFileConfig(overrideConfigPath, config); err != nil {
		t.Fatal(err)
	}

	var called bool
	runOnce = func(_ context.Context, config pmgbot.DaemonConfig) error {
		called = true
		if config.Timeout != 7*time.Minute {
			t.Fatalf("got timeout %s, want 7m0s", config.Timeout)
		}
		return nil
	}

	root := rootCmd()
	root.SetArgs([]string{"run"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected run command to run one cycle")
	}
}

func TestCheckCommandRunsDryRun(t *testing.T) {
	originalRunCheck := runCheck
	t.Cleanup(func() { runCheck = originalRunCheck })

	var called bool
	runCheck = func(_ context.Context, config pmgbot.DaemonConfig) error {
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
	root.SetArgs([]string{"--config", configPath, "check"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected check command to run dry-run")
	}
}

func TestAnalyzeCommandRunsSpamAnalysis(t *testing.T) {
	originalRunAnalyze := runAnalyze
	t.Cleanup(func() { runAnalyze = originalRunAnalyze })

	var called bool
	runAnalyze = func(_ context.Context, config pmgbot.DaemonConfig, minCount int, output io.Writer) error {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		if minCount != 3 {
			t.Fatalf("got min count %d, want 3", minCount)
		}
		_, err := io.WriteString(output, "sender@example.com - Subject - 2\n")
		return err
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "analyze", "--min-count", "3"})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected analyze command to run spam analysis")
	}
	if !strings.Contains(out.String(), "sender@example.com - Subject - 2") {
		t.Fatalf("got output %q", out.String())
	}
}

func TestAnalyzeCommandRunsSpamJSONAnalysis(t *testing.T) {
	originalRunAnalyze := runAnalyze
	originalRunAnalyzeJSON := runAnalyzeJSON
	t.Cleanup(func() {
		runAnalyze = originalRunAnalyze
		runAnalyzeJSON = originalRunAnalyzeJSON
	})

	runAnalyze = func(context.Context, pmgbot.DaemonConfig, int, io.Writer) error {
		t.Fatal("analyze --json must not call pmgsh analyze")
		return nil
	}

	var called bool
	runAnalyzeJSON = func(_ context.Context, config pmgbot.DaemonConfig, path string, minCount int, output io.Writer) error {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		if path != "spam.json" {
			t.Fatalf("got json path %q, want spam.json", path)
		}
		if minCount != 4 {
			t.Fatalf("got min count %d, want 4", minCount)
		}
		_, err := io.WriteString(output, "Subject - 2\n")
		return err
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "analyze", "--json", "spam.json", "--min-count", "4"})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected analyze --json command to run json analysis")
	}
	if !strings.Contains(out.String(), "Subject - 2") {
		t.Fatalf("got output %q", out.String())
	}
}

func TestGenerateCommandRunsJSONGenerator(t *testing.T) {
	originalGenerate := runGenerate
	originalGenerateJSON := runGenerateJSON
	t.Cleanup(func() {
		runGenerate = originalGenerate
		runGenerateJSON = originalGenerateJSON
	})

	runGenerate = func(context.Context, pmgbot.DaemonConfig, pmgbot.RuleGenerationConfig, io.Writer) error {
		t.Fatal("generate --json must not call pmgsh generator")
		return nil
	}

	var called bool
	runGenerateJSON = func(path string, config pmgbot.RuleGenerationConfig, output io.Writer) error {
		called = true
		if path != "spam.json" {
			t.Fatalf("got json path %q, want spam.json", path)
		}
		if config.Action != "deliver" || config.MinCount != 3 {
			t.Fatalf("got config %#v", config)
		}
		_, err := io.WriteString(output, "rules:\n")
		return err
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "generate", "--json", "spam.json", "--action", "deliver", "--min-count", "3"})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected generate command to run generator")
	}
	if !strings.Contains(out.String(), "rules:") {
		t.Fatalf("got output %q", out.String())
	}
}

func TestGenerateCommandRunsPMGGenerator(t *testing.T) {
	originalGenerate := runGenerate
	originalGenerateJSON := runGenerateJSON
	t.Cleanup(func() {
		runGenerate = originalGenerate
		runGenerateJSON = originalGenerateJSON
	})

	runGenerateJSON = func(string, pmgbot.RuleGenerationConfig, io.Writer) error {
		t.Fatal("generate without --json must not call json generator")
		return nil
	}

	var called bool
	runGenerate = func(_ context.Context, config pmgbot.DaemonConfig, ruleConfig pmgbot.RuleGenerationConfig, output io.Writer) error {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		if ruleConfig.Action != "deliver" || ruleConfig.MinCount != 4 {
			t.Fatalf("got rule config %#v", ruleConfig)
		}
		_, err := io.WriteString(output, "rules:\n")
		return err
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "generate", "--action", "deliver", "--min-count", "4"})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected generate command to run pmg generator")
	}
	if !strings.Contains(out.String(), "rules:") {
		t.Fatalf("got output %q", out.String())
	}
}

func commandExists(root *cobra.Command, name string) bool {
	cmd, _, err := root.Find([]string{name})
	return err == nil && cmd != nil && cmd.Name() == name
}
