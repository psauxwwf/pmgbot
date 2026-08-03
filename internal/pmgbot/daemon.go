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
	deliverPatterns, deletePatterns, err := compileDaemonPatterns(config)
	if err != nil {
		return err
	}

	return runDaemonOnce(ctx, config, deliverPatterns, deletePatterns)
}

func Daemon(ctx context.Context, config DaemonConfig) error {
	if config.Every <= 0 {
		return fmt.Errorf("daemon every must be greater than zero")
	}
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	deliverPatterns, deletePatterns, err := compileDaemonPatterns(config)
	if err != nil {
		return err
	}

	slog.Info("starting pmgbot daemon",
		"every", config.Every.String(),
		"timeout", config.Timeout.String(),
		"deliver_fields", len(deliverPatterns),
		"delete_fields", len(deletePatterns),
	)

	for {
		if err := runDaemonOnce(ctx, config, deliverPatterns, deletePatterns); err != nil {
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

func compileDaemonPatterns(config DaemonConfig) (compiledFieldPatterns, compiledFieldPatterns, error) {
	deliverPatterns, err := compileFieldPatterns("deliver", config.Deliver)
	if err != nil {
		return nil, nil, err
	}
	deletePatterns, err := compileFieldPatterns("delete", config.Delete)
	if err != nil {
		return nil, nil, err
	}

	return deliverPatterns, deletePatterns, nil
}

func runDaemonOnce(
	ctx context.Context,
	config DaemonConfig,
	deliverPatterns compiledFieldPatterns,
	deletePatterns compiledFieldPatterns,
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
		action, ok := decideQuarantineAction(message, deliverPatterns, deletePatterns)
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

		actionCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		err = applyQuarantineActionContext(actionCtx, id, action)
		cancel()
		if err != nil {
			actionErrors = append(actionErrors, err)
			slog.Error("quarantine spam action failed", "id", id, "action", action, "error", err)
			continue
		}

		if action == quarantineActionDeliver {
			delivered++
		} else {
			deleted++
		}
		slog.Info("quarantine spam action applied", "id", id, "action", action)
	}
	slog.Info("daemon quarantine spam processed", "delivered", delivered, "deleted", deleted, "skipped", skipped, "errors", len(actionErrors))

	return errors.Join(actionErrors...)
}
