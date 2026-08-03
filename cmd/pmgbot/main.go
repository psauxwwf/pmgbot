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
	runCheck  = pmgbot.Check
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

			return cmd.Help()
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

	root.AddCommand(runCmd(&config), checkCmd(&config), daemonCmd(&config))

	return root
}

func runCmd(logConfig *cliConfig) *cobra.Command {
	run := &cobra.Command{
		Use:           "run",
		Short:         "Run one PMG spam quarantine processing cycle",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if logConfig.SaveConfig {
				return saveDefaultConfig(logConfig.ConfigPath)
			}

			return runConfigured(cmd.Context(), logConfig.ConfigPath, runOnce)
		},
	}

	return run
}

func checkCmd(logConfig *cliConfig) *cobra.Command {
	check := &cobra.Command{
		Use:           "check",
		Short:         "Log matching PMG spam quarantine actions without applying them",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if logConfig.SaveConfig {
				return saveDefaultConfig(logConfig.ConfigPath)
			}

			return runConfigured(cmd.Context(), logConfig.ConfigPath, runCheck)
		},
	}

	return check
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
		Rules: pmgbot.Rules{
			{
				Name:   "Delete webmaster registrations",
				Action: "delete",
				When:   pmgbot.RuleGroups{{"subject": {`^\[SPAM\]: Зарегистрировался новый пользователь$`}}},
			},
			{
				Name:   "Deliver explicitly allowed subjects",
				Action: "deliver",
				When:   pmgbot.RuleGroups{{"subject": {`^\[ALLOW\]`, `(?i)важный отчет`, `(?i)backup completed`}}},
			},
			{
				Name:   "Delete obvious sender domains",
				Action: "delete",
				When:   pmgbot.RuleGroups{{"envelope_sender": {`^[^@]+@bad-domain\.ru$`, `^[^@]+@([^.@]+\.)*sendsay\.ru$`, `^bounce-[^@]*@[^@]+$`}}},
			},
			{
				Name:   "Delete webmaster registration exact sender and subject",
				Action: "delete",
				When: pmgbot.RuleGroups{{
					"envelope_sender": {`^webmaster@rc\.ffff\.ru$`},
					"subject":         {`^\[SPAM\]: Зарегистрировался новый пользователь$`},
				}},
			},
			{
				Name:   "Deliver monitoring to admins",
				Action: "deliver",
				When: pmgbot.RuleGroups{{
					"from":     {`(?i)monitoring|security alert`},
					"receiver": {`^admin@example\.com$`, `^support@example\.com$`},
				}},
			},
			{
				Name:   "Delete webmaster registration or payment confirmations",
				Action: "delete",
				When: pmgbot.RuleGroups{{
					"envelope_sender": {`^webmaster@rc\.ffff\.ru$`},
					"subject": {
						`^\[SPAM\]: Зарегистрировался новый пользователь$`,
						`^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$`,
					},
				}},
			},
			{
				Name:   "Delete payment subjects from noisy senders",
				Action: "delete",
				When: pmgbot.RuleGroups{{
					"envelope_sender": {`^[^@]+@promo\.example\.com$`, `^[^@]+@mailing\.example\.net$`},
					"subject":         {`(?i)оплата|платеж|invoice`},
				}},
			},
			{
				Name:   "Delete marketing senders with spam subjects",
				Action: "delete",
				When: pmgbot.RuleGroups{{
					"envelope_sender": {`^[^@]+@promo\.example\.com$`, `^[^@]+@offers\.example\.org$`},
					"subject":         {`(?i)limited offer`, `(?i)act now`, `(?i)скидка .* только сегодня`},
				}},
			},
			{
				Name:   "Deliver trusted departments to service mailboxes",
				Action: "deliver",
				When: pmgbot.RuleGroups{{
					"from":     {`(?i)Finance Department`, `(?i)Security Team`},
					"receiver": {`^accounting@example\.com$`, `^security@example\.com$`},
				}},
			},
			{
				Name:   "Delete fake invoices to accounting",
				Action: "delete",
				When: pmgbot.RuleGroups{{
					"envelope_sender": {`^[^@]+@unknown-billing\.example\.com$`},
					"receiver":        {`^accounting@example\.com$`},
					"subject":         {`(?i)invoice|счет|оплата`},
				}},
			},
			{
				Name:   "Deliver internal operational alerts",
				Action: "deliver",
				When: pmgbot.RuleGroups{{
					"from":     {`(?i)Operations Center`},
					"receiver": {`^admin@example\.com$`},
					"subject":  {`(?i)incident resolved`, `(?i)service restored`},
				}},
			},
			{
				Name:   "Deliver critical service messages",
				Action: "deliver",
				When: pmgbot.RuleGroups{
					{"envelope_sender": {`^postmaster@example\.com$`}, "subject": {`(?i)delivery status notification`}},
					{"from": {`(?i)Security Alert`}, "subject": {`(?i)critical|urgent`}},
				},
			},
			{
				Name:   "Delete credential phishing variants",
				Action: "delete",
				When: pmgbot.RuleGroups{
					{"subject": {`(?i)password expired|verify account`}},
					{"from": {`(?i)helpdesk|support`}, "subject": {`(?i)confirm your mailbox`}},
					{"envelope_sender": {`^[^@]+@login-alerts\.example\.ru$`}, "receiver": {`^user@example\.com$`}},
				},
			},
			{
				Name:   "Delete payment phishing to finance mailboxes",
				Action: "delete",
				When: pmgbot.RuleGroups{{
					"envelope_sender": {`^[^@]+@payment-notice\.example\.ru$`, `^[^@]+@bank-alert\.example\.net$`},
					"receiver":        {`^accounting@example\.com$`, `^finance@example\.com$`},
					"subject":         {`(?i)payment confirmation required`, `(?i)подтвердите платеж`},
				}},
			},
			{
				Name:   "Delete mixed phishing campaign",
				Action: "delete",
				When: pmgbot.RuleGroups{
					{
						"envelope_sender": {`^[^@]+@secure-mail\.example\.ru$`, `^[^@]+@account-check\.example\.ru$`},
						"subject":         {`(?i)account suspended`, `(?i)security verification`},
					},
					{
						"from":     {`(?i)IT Support`, `(?i)Mail Administrator`},
						"receiver": {`^user@example\.com$`, `^test@example\.com$`},
						"subject":  {`(?i)update your password`, `(?i)mailbox quota exceeded`},
					},
				},
			},
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
