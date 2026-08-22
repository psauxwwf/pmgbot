package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"pmgbot/internal/pmgbot"
	"pmgbot/pkg/pmg"
)

func TestRootCommandsAndFlags(t *testing.T) {
	root := rootCmd()

	for _, name := range []string{"parse", "import"} {
		if commandExists(root, name) {
			t.Fatalf("obsolete command %q found", name)
		}
	}

	for _, name := range []string{"run", "check", "get", "analyze", "generate", "daemon"} {
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
	for _, name := range []string{"run", "check", "get", "analyze", "generate", "daemon"} {
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
	if config.Daemon.Cron != defaultDaemonCron {
		t.Fatalf("got daemon cron %q, want %q", config.Daemon.Cron, defaultDaemonCron)
	}
	if time.Duration(config.Daemon.Timeout) != defaultDaemonTimeout {
		t.Fatalf("got daemon timeout %s, want %s", time.Duration(config.Daemon.Timeout), defaultDaemonTimeout)
	}
	if len(config.Rules) != 16 {
		t.Fatalf("got %d rules, want 16", len(config.Rules))
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
	if config.Rules[6].Name != "Delete repeated subjects by count examples" || config.Rules[6].When[0]["subject"][0] != "[===]" || config.Rules[6].When[0]["count"][0] != "3" || config.Rules[6].When[4]["count"][0] != "<3" {
		t.Fatalf("got rules %#v", config.Rules)
	}
	if config.Rules[15].Name != "Delete mixed phishing campaign" || len(config.Rules[15].When) != 2 {
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

	runOnce = func(_ context.Context, config pmgbot.DaemonConfig, _ io.Writer) error {
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

func TestGetCommandPrintsQuarantineContentJSON(t *testing.T) {
	originalRunGet := runGet
	t.Cleanup(func() { runGet = originalRunGet })

	var called bool
	runGet = func(_ context.Context, id string) (pmg.SpamContent, error) {
		called = true
		if id != "C1R1691568T97183293" {
			t.Fatalf("got id %q", id)
		}

		return pmg.SpamContent{
			Bytes:          34185,
			Content:        "content",
			EnvelopeSender: "sender@example.com",
			File:           "cluster/1/spam/05/message",
			From:           "Sender <sender@example.com>",
			Header:         "Return-Path: sender@example.com\n",
			ID:             id,
			Receiver:       "receiver@example.com",
			SpamInfo:       []pmg.SpamInfo{{Name: "BAYES_00", Desc: "Bayes", Score: -1.9}},
			SpamLevel:      5,
			Subject:        "[SPAM]: Test",
			Time:           1787414437,
			Raw:            "raw message",
		}, nil
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "get", "C1R1691568T97183293"})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected get command to load quarantine content")
	}

	got := out.String()
	for _, want := range []string{
		`"id": "C1R1691568T97183293"`,
		`"spaminfo": [`,
		`"raw": "raw message"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
	if strings.LastIndex(got, `"raw"`) < strings.LastIndex(got, `"time"`) {
		t.Fatalf("raw must be after time in output %q", got)
	}
}

func TestRunCommandRunsOneCycle(t *testing.T) {
	originalRunOnce := runOnce
	t.Cleanup(func() { runOnce = originalRunOnce })

	var called bool
	runOnce = func(_ context.Context, config pmgbot.DaemonConfig, output io.Writer) error {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		slog.Info("run action log", "id", "id", "action", "delete")
		_, err := io.WriteString(output, "id | [delete:Rule] | sender@example.com | From | receiver@example.com | Subject\n---\nsummary | total: 1 | deliver: 0 | delete: 1 | skip: 0 | errors: 0\n")
		return err
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "pmgbot.yaml")
	logPath := filepath.Join(tmpDir, "pmgbot.json")
	config := defaultFileConfig(time.Now())
	config.LogPath = logPath
	if err := pmgbot.SaveFileConfig(configPath, config); err != nil {
		t.Fatal(err)
	}

	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "run"})
	var out bytes.Buffer
	var errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected run command to run one cycle")
	}
	if !strings.Contains(out.String(), "summary | total: 1 | deliver: 0 | delete: 1 | skip: 0 | errors: 0") {
		t.Fatalf("got output %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("run must not write logs to stderr, got %q", errOut.String())
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), `"msg":"run action log"`) || !strings.Contains(string(logData), `"action":"delete"`) {
		t.Fatalf("got log file %q", string(logData))
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
	runOnce = func(_ context.Context, config pmgbot.DaemonConfig, _ io.Writer) error {
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
	runCheck = func(_ context.Context, config pmgbot.DaemonConfig, output io.Writer) error {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		slog.Info("this log must not be printed by check")
		_, err := io.WriteString(output, "delete-id | [delete:Delete spam] | bad@example.com | Bad | user@example.com | Lottery\n---\nsummary | total: 2 | deliver: 0 | delete: 1 | skip: 1 | errors: 0\n")
		return err
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "check"})
	var out bytes.Buffer
	var errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected check command to run dry-run")
	}
	if !strings.Contains(out.String(), "delete-id | [delete:Delete spam]") || !strings.Contains(out.String(), "summary | total: 2 | deliver: 0 | delete: 1 | skip: 1 | errors: 0") {
		t.Fatalf("got output %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("check must not write logs to stderr, got %q", errOut.String())
	}
}

func TestCheckCommandWritesMarkdownReport(t *testing.T) {
	originalRunCheckReport := runCheckReport
	t.Cleanup(func() { runCheckReport = originalRunCheckReport })

	var called bool
	runCheckReport = func(_ context.Context, config pmgbot.DaemonConfig, output io.Writer, report bool) (string, error) {
		called = true
		if config.Timeout != defaultDaemonTimeout {
			t.Fatalf("got timeout %s, want %s", config.Timeout, defaultDaemonTimeout)
		}
		if !report {
			t.Fatal("expected report flag")
		}
		_, err := io.WriteString(output, "summary | total: 1 | deliver: 0 | delete: 0 | skip: 1 | errors: 0\n")
		return "pmgbot-check-report-20260822-083015-123456789.md", err
	}

	configPath := filepath.Join(t.TempDir(), "pmgbot.yaml")
	if err := pmgbot.SaveFileConfig(configPath, defaultFileConfig(time.Now())); err != nil {
		t.Fatal(err)
	}

	root := rootCmd()
	root.SetArgs([]string{"--config", configPath, "check", "--report"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected check command to write markdown report")
	}
	if !strings.Contains(out.String(), "report | path: pmgbot-check-report-20260822-083015-123456789.md") {
		t.Fatalf("got output %q", out.String())
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
		_, err := io.WriteString(output, "sender@example.com | Subject | 2\n")
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
	if !strings.Contains(out.String(), "sender@example.com | Subject | 2") {
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
		_, err := io.WriteString(output, "Subject | 2\n")
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
	if !strings.Contains(out.String(), "Subject | 2") {
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
