package pmgbot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	quarantineSpamContext        = pmgQuarantineSpamContext
	applyQuarantineActionContext = pmgApplyQuarantineActionContext
)

func RunOnce(ctx context.Context, config DaemonConfig) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	return runDaemonOnce(ctx, config, rules)
}

func Check(ctx context.Context, config DaemonConfig) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	return runDaemonCheck(ctx, config, rules)
}

func Daemon(ctx context.Context, config DaemonConfig) error {
	if config.Every <= 0 {
		return fmt.Errorf("daemon every must be greater than zero")
	}
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	slog.Info("starting pmgbot daemon",
		"every", config.Every.String(),
		"timeout", config.Timeout.String(),
		"rules", len(rules),
	)

	for {
		if err := runDaemonOnce(ctx, config, rules); err != nil {
			slog.Error("pmgbot daemon cycle failed", "error", err)
		} else {
			slog.Info("pmgbot daemon cycle completed")
		}
		if ctx.Err() != nil {
			slog.Info("stopping pmgbot daemon", "reason", ctx.Err())
			return nil
		}

		timer := time.NewTimer(config.Every)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			slog.Info("stopping pmgbot daemon", "reason", ctx.Err())
			return nil
		case <-timer.C:
		}
	}
}

func compileDaemonRules(config DaemonConfig) ([]compiledRule, error) {
	return compileRules(config.Rules)
}

func runDaemonOnce(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
) error {
	return runDaemonCycle(ctx, config, rules, false)
}

func runDaemonCheck(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
) error {
	return runDaemonCycle(ctx, config, rules, true)
}

func runDaemonCycle(
	ctx context.Context,
	config DaemonConfig,
	rules []compiledRule,
	dryRun bool,
) error {
	cycleCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	messages, err := quarantineSpamContext(cycleCtx)
	cancel()
	if err != nil {
		return err
	}
	slog.Info("daemon quarantine spam loaded", "count", len(messages))
	if len(messages) == 0 {
		return nil
	}

	var actionErrors []error
	var delivered, deleted, skipped int
	for _, message := range messages {
		action, ruleName, ok := decideQuarantineAction(message, rules)
		if !ok {
			skipped++
			continue
		}

		id, err := quarantineSpamID(message)
		if err != nil {
			actionErrors = append(actionErrors, err)
			slog.Error("quarantine spam action skipped", "error", err, "message", message)
			continue
		}
		if dryRun {
			if action == quarantineActionDeliver {
				delivered++
			} else {
				deleted++
			}
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
			continue
		}

		actionCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		err = applyQuarantineActionContext(actionCtx, id, action)
		cancel()
		if err != nil {
			actionErrors = append(actionErrors, err)
			slog.Error("quarantine spam action failed", "id", id, "action", action, "rule", ruleName, "error", err)
			continue
		}

		if action == quarantineActionDeliver {
			delivered++
		} else {
			deleted++
		}
		slog.Info("quarantine spam action applied", "id", id, "action", action, "rule", ruleName)
	}
	if dryRun {
		slog.Info("daemon quarantine spam checked", "deliver", delivered, "delete", deleted, "skipped", skipped, "errors", len(actionErrors))
	} else {
		slog.Info("daemon quarantine spam processed", "delivered", delivered, "deleted", deleted, "skipped", skipped, "errors", len(actionErrors))
	}

	return errors.Join(actionErrors...)
}
