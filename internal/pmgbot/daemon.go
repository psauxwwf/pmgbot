package pmgbot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/go-co-op/gocron/v2"
)

type quarantineSpamFunc func(context.Context) ([]quarantineSpamMessage, error)
type applyQuarantineActionFunc func(context.Context, string, quarantineAction) error

type daemonCycleActionRow struct {
	ID       string
	Action   quarantineAction
	RuleName string
	Message  quarantineSpamMessage
	Error    error
}

type daemonCycleReport struct {
	DryRun          bool
	Total           int
	Delivered       int
	Deleted         int
	Skipped         int
	Errors          int
	Actions         []daemonCycleActionRow
	SkippedMessages []quarantineSpamMessage
}

func RunOnce(ctx context.Context, config DaemonConfig) error {
	return RunOnceOutput(ctx, config, io.Discard)
}

func RunOnceOutput(ctx context.Context, config DaemonConfig, output io.Writer) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	_, err = runDaemonOnceReportOutput(ctx, config, rules, pmgQuarantineSpamContext, pmgApplyQuarantineActionContext, output)
	return err
}

func RunOnceOutputReport(ctx context.Context, config DaemonConfig, output io.Writer, writeReport bool) (string, error) {
	if config.Timeout <= 0 {
		return "", fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return "", err
	}

	report, err := runDaemonOnceReportOutput(ctx, config, rules, pmgQuarantineSpamContext, pmgApplyQuarantineActionContext, output)
	if !writeReport {
		return "", err
	}

	path, reportErr := WriteDaemonMarkdownReport("run", report)
	return path, errors.Join(err, reportErr)
}

func Check(ctx context.Context, config DaemonConfig) error {
	return CheckOutput(ctx, config, io.Discard)
}

func CheckOutput(ctx context.Context, config DaemonConfig, output io.Writer) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	_, err = runDaemonCheckReportOutput(ctx, config, rules, pmgQuarantineSpamContext, output)
	return err
}

func CheckOutputReport(ctx context.Context, config DaemonConfig, output io.Writer, writeReport bool) (string, error) {
	if config.Timeout <= 0 {
		return "", fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return "", err
	}

	report, err := runDaemonCheckReportOutput(ctx, config, rules, pmgQuarantineSpamContext, output)
	if !writeReport {
		return "", err
	}

	path, reportErr := WriteDaemonMarkdownReport("check", report)
	return path, errors.Join(err, reportErr)
}

func Daemon(ctx context.Context, config DaemonConfig) error {
	jobDefinition, scheduleText, err := daemonJobDefinition(config)
	if err != nil {
		return err
	}
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	slog.Info("starting pmgbot daemon",
		"schedule", scheduleText,
		"timeout", config.Timeout.String(),
		"rules", len(rules),
	)

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("create scheduler: %w", err)
	}
	if _, err := scheduler.NewJob(
		jobDefinition,
		gocron.NewTask(func() {
			if err := runDaemonOnce(ctx, config, rules, pmgQuarantineSpamContext, pmgApplyQuarantineActionContext); err != nil {
				slog.Error("pmgbot daemon cycle failed", "error", err)
			} else {
				slog.Info("pmgbot daemon cycle completed")
			}
		}),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	); err != nil {
		return fmt.Errorf("schedule pmgbot daemon: %w", err)
	}

	scheduler.Start()
	<-ctx.Done()
	slog.Info("stopping pmgbot daemon", "reason", ctx.Err())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()
	if err := scheduler.ShutdownWithContext(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown scheduler: %w", err)
	}

	return nil
}

func daemonJobDefinition(config DaemonConfig) (gocron.JobDefinition, string, error) {
	cron := strings.TrimSpace(config.Cron)
	if cron != "" {
		return gocron.CronJob(cron, cronIncludesSeconds(cron)), "cron " + cron, nil
	}

	return nil, "", fmt.Errorf("daemon cron must not be empty")
}

func cronIncludesSeconds(cron string) bool {
	fields := strings.Fields(cron)
	if len(fields) > 0 && (strings.HasPrefix(fields[0], "TZ=") || strings.HasPrefix(fields[0], "CRON_TZ=")) {
		fields = fields[1:]
	}

	return len(fields) == 6
}

func compileDaemonRules(config DaemonConfig) ([]compiledRule, error) {
	return compileRules(config.Rules)
}

func runDaemonOnce(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	quarantineSpam quarantineSpamFunc,
	applyQuarantineAction applyQuarantineActionFunc,
) error {
	_, err := runDaemonOnceReportOutput(ctx, config, rules, quarantineSpam, applyQuarantineAction, io.Discard)
	return err
}

func runDaemonOnceReport(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	quarantineSpam quarantineSpamFunc,
	applyQuarantineAction applyQuarantineActionFunc,
) (daemonCycleReport, error) {
	return runDaemonOnceReportOutput(ctx, config, rules, quarantineSpam, applyQuarantineAction, io.Discard)
}

func runDaemonOnceReportOutput(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	quarantineSpam quarantineSpamFunc,
	applyQuarantineAction applyQuarantineActionFunc,
	output io.Writer,
) (daemonCycleReport, error) {
	return runDaemonCycle(ctx, config, rules, false, quarantineSpam, applyQuarantineAction, output)
}

func runDaemonCheck(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	quarantineSpam quarantineSpamFunc,
) error {
	_, err := runDaemonCheckReportOutput(ctx, config, rules, quarantineSpam, io.Discard)
	return err
}

func runDaemonCheckReport(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	quarantineSpam quarantineSpamFunc,
) (daemonCycleReport, error) {
	return runDaemonCheckReportOutput(ctx, config, rules, quarantineSpam, io.Discard)
}

func runDaemonCheckReportOutput(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	quarantineSpam quarantineSpamFunc,
	output io.Writer,
) (daemonCycleReport, error) {
	return runDaemonCycle(ctx, config, rules, true, quarantineSpam, nil, output)
}

func runDaemonCycle(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	dryRun bool,
	quarantineSpam quarantineSpamFunc,
	applyQuarantineAction applyQuarantineActionFunc,
	output io.Writer,
) (daemonCycleReport, error) {
	cycleCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	messages, err := quarantineSpam(cycleCtx)
	cancel()
	if err != nil {
		return daemonCycleReport{DryRun: dryRun}, err
	}
	report := daemonCycleReport{DryRun: dryRun, Total: len(messages)}
	slog.Info("daemon quarantine spam loaded", "count", len(messages))
	if len(messages) == 0 {
		return report, writeDaemonCycleSummary(output, report)
	}

	var actionErrors []error
	for _, message := range messages {
		action, ruleName, ok := decideQuarantineActionForMessages(message, messages, rules)
		if !ok {
			report.Skipped++
			report.SkippedMessages = append(report.SkippedMessages, message)
			continue
		}

		id, err := quarantineSpamID(message)
		if err != nil {
			actionErrors = append(actionErrors, err)
			report.Errors++
			row := daemonCycleActionRow{Action: action, RuleName: ruleName, Message: message, Error: err}
			report.Actions = append(report.Actions, row)
			slog.Error("quarantine spam action skipped", "error", err, "message", message)
			if err := writeDaemonCycleAction(output, row); err != nil {
				return report, errors.Join(errors.Join(actionErrors...), err)
			}
			continue
		}
		if dryRun {
			if action == quarantineActionDeliver {
				report.Delivered++
			} else {
				report.Deleted++
			}
			row := daemonCycleActionRow{ID: id, Action: action, RuleName: ruleName, Message: message}
			report.Actions = append(report.Actions, row)
			slog.Info("quarantine spam action planned",
				"id", id,
				"action", action,
				"rule", ruleName,
				"envelope_sender", message.EnvelopeSender,
				"from", message.From,
				"receiver", message.Receiver,
				"subject", message.Subject,
				"spamlevel", message.SpamLevel,
				"bytes", message.Bytes,
				"time", message.Time,
			)
			if err := writeDaemonCycleAction(output, row); err != nil {
				return report, errors.Join(errors.Join(actionErrors...), err)
			}
			continue
		}

		actionCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		err = applyQuarantineAction(actionCtx, id, action)
		cancel()
		if err != nil {
			actionErrors = append(actionErrors, err)
			report.Errors++
			row := daemonCycleActionRow{ID: id, Action: action, RuleName: ruleName, Message: message, Error: err}
			report.Actions = append(report.Actions, row)
			slog.Error("quarantine spam action failed", "id", id, "action", action, "rule", ruleName, "error", err)
			if err := writeDaemonCycleAction(output, row); err != nil {
				return report, errors.Join(errors.Join(actionErrors...), err)
			}
			continue
		}

		if action == quarantineActionDeliver {
			report.Delivered++
		} else {
			report.Deleted++
		}
		row := daemonCycleActionRow{ID: id, Action: action, RuleName: ruleName, Message: message}
		report.Actions = append(report.Actions, row)
		slog.Info(
			"quarantine spam action applied",
			"id",
			id,
			"action",
			action,
			"rule",
			ruleName,
			"envelope_sender", message.EnvelopeSender,
			"from", message.From,
			"receiver", message.Receiver,
			"subject", message.Subject,
		)
		if err := writeDaemonCycleAction(output, row); err != nil {
			return report, errors.Join(errors.Join(actionErrors...), err)
		}
	}
	if dryRun {
		slog.Info("daemon quarantine spam checked", "deliver", report.Delivered, "delete", report.Deleted, "skipped", report.Skipped, "errors", len(actionErrors))
	} else {
		slog.Info("daemon quarantine spam processed", "delivered", report.Delivered, "deleted", report.Deleted, "skipped", report.Skipped, "errors", len(actionErrors))
	}

	return report, errors.Join(errors.Join(actionErrors...), writeDaemonCycleSummary(output, report))
}

func writeDaemonCycleReport(output io.Writer, report daemonCycleReport) error {
	for _, action := range report.Actions {
		if err := writeDaemonCycleAction(output, action); err != nil {
			return err
		}
	}
	return writeDaemonCycleSummary(output, report)
}

func writeDaemonCycleAction(output io.Writer, action daemonCycleActionRow) error {
	if _, err := fmt.Fprintf(
		output,
		"%s | %s\n%s | %s | %s | %s",
		action.Message.Subject,
		daemonCycleActionID(action.ID),
		action.Message.EnvelopeSender,
		action.Message.From,
		action.Message.Receiver,
		daemonCycleActionText(action.Action, action.RuleName),
	); err != nil {
		return fmt.Errorf("write daemon cycle report: %w", err)
	}
	if action.Error != nil {
		if _, err := fmt.Fprintf(output, " | error: %s", action.Error); err != nil {
			return fmt.Errorf("write daemon cycle report: %w", err)
		}
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return fmt.Errorf("write daemon cycle report: %w", err)
	}
	if _, err := fmt.Fprintln(output, "---"); err != nil {
		return fmt.Errorf("write daemon cycle report: %w", err)
	}

	return nil
}

func writeDaemonCycleSummary(output io.Writer, report daemonCycleReport) error {
	if _, err := fmt.Fprintf(
		output,
		"summary | total: %d | deliver: %d | delete: %d | skip: %d | errors: %d\n",
		report.Total,
		report.Delivered,
		report.Deleted,
		report.Skipped,
		report.Errors,
	); err != nil {
		return fmt.Errorf("write daemon cycle report: %w", err)
	}

	return nil
}

func daemonCycleActionID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "-"
	}

	return id
}

func daemonCycleActionText(action quarantineAction, ruleName string) string {
	return fmt.Sprintf("[%s:%s]", action, ruleName)
}
