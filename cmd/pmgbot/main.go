package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"pmgbot/internal/pmgbot"
	pmgcmd "pmgbot/pkg/cmd"
)

const (
	defaultDaemonEvery   = 15 * time.Minute
	defaultDaemonTimeout = 10 * time.Minute
	defaultConfigPath    = "pmgbot.yaml"
	defaultLogLevel      = "info"
)

type cliConfig struct {
	ConfigPath string
	SaveConfig bool
}

var (
	runOnce   = pmgbot.RunOnce
	runDaemon = pmgbot.Daemon
)

func main() {
	if err := fang.Execute(context.Background(), rootCmd(), fang.WithoutVersion()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var config cliConfig

	root := &cobra.Command{
		Use:           "pmgbot",
		Short:         "Manage PMG spam quarantine from regexp rules",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if config.SaveConfig {
				return saveDefaultConfig(config.ConfigPath)
			}

			return runConfigured(cmd.Context(), config.ConfigPath, runOnce)
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
	root.SetHelpCommand(&cobra.Command{Hidden: true})
	root.PersistentFlags().StringVar(
		&config.ConfigPath,
		"config",
		defaultConfigPath,
		"path to yaml config for daemon and --save-config",
	)
	root.PersistentFlags().BoolVar(
		&config.SaveConfig,
		"save-config",
		false,
		"save default yaml config and exit",
	)

	root.AddCommand(daemonCmd(&config))

	return root
}

func daemonCmd(logConfig *cliConfig) *cobra.Command {
	daemon := &cobra.Command{
		Use:           "daemon",
		Short:         "Periodically deliver or delete PMG spam quarantine messages",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if logConfig.SaveConfig {
				return saveDefaultConfig(logConfig.ConfigPath)
			}

			if err := runConfigured(cmd.Context(), logConfig.ConfigPath, runDaemon); err != nil {
				slog.Error("pmgbot daemon failed", "error", err)
				return err
			}

			return nil
		},
	}

	return daemon
}

func runConfigured(
	ctx context.Context,
	configPath string,
	run func(context.Context, pmgbot.DaemonConfig) error,
) error {
	fileConfig, err := pmgbot.LoadFileConfig(configPath)
	if err != nil {
		return err
	}
	pmgcmd.SetSudo(fileConfig.Sudo)

	if err := configureLogger(fileConfig.LogLevel, fileConfig.LogPath); err != nil {
		return err
	}

	return run(ctx, fileConfig.DaemonConfig())
}

func defaultFileConfig(_ time.Time) pmgbot.FileConfig {
	return pmgbot.FileConfig{
		LogLevel: defaultLogLevel,
		LogPath:  "",
		Sudo:     true,
		Daemon: pmgbot.FileDaemonConfig{
			Every:   pmgbot.Duration(defaultDaemonEvery),
			Timeout: pmgbot.Duration(defaultDaemonTimeout),
		},
		Deliver: pmgbot.FieldPatterns{
			"envelope_sender": {`^trusted@example\.com$`, `^[^@]+@partner\.example\.com$`, `^no-reply@alerts\.example\.com$`},
			"from":            {`(?i)Trusted Sender <trusted@example\.com>`, `(?i)monitoring|security alert`},
			"receiver":        {`^vip@example\.com$`, `^admin@example\.com$`, `^support@example\.com$`},
			"subject":         {`(?i)important report|delivery required`, `(?i)invoice approved|backup completed`, `^\[ALLOW\]`},
		},
		Delete: pmgbot.FieldPatterns{
			"envelope_sender": {`^[^@]+@bad-domain\.ru$`, `^[^@]+@([^.@]+\.)*sendsay\.ru$`, `^bounce-[^@]*@[^@]+$`, `^[^@]+@[^@]+\.ru$`},
			"from":            {`(?i)casino|lottery|crypto`, `(?i)free money|winner|prize`, `(?i)loan approved`},
			"receiver":        {`^user@example\.com$`, `^test@example\.com$`, `^spamtrap@example\.com$`},
			"subject":         {`(?i)crypto|urgent payment|casino`, `(?i)limited offer|act now`, `(?i)password expired|verify account`},
		},
	}
}

func saveDefaultConfig(path string) error {
	if err := pmgbot.SaveFileConfig(path, defaultFileConfig(time.Now())); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "saved config to %s\n", path)
	return nil
}

func configureLogger(levelText, logPath string) error {
	var parsedLevel slog.Level
	if err := parsedLevel.UnmarshalText([]byte(levelText)); err != nil {
		return fmt.Errorf("invalid log level %q: %w", levelText, err)
	}

	h := []slog.Handler{
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     parsedLevel,
		}),
	}

	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
			return fmt.Errorf("failed to create log dir for %q: %w", logPath, err)
		}

		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open log file %q: %w", logPath, err)
		}

		h = append(h,
			slog.NewJSONHandler(logFile, &slog.HandlerOptions{
				AddSource: true,
				Level:     parsedLevel,
			}),
		)
	}

	slog.SetDefault(slog.New(slog.NewMultiHandler(h...)))

	return nil
}
