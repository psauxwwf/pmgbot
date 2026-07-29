package pmgbot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

func Daemon(ctx context.Context, config DaemonConfig) error {
	if config.Before <= 0 {
		return fmt.Errorf("daemon before must be greater than zero")
	}
	if config.Every <= 0 {
		return fmt.Errorf("daemon every must be greater than zero")
	}
	if config.ParseTimeout <= 0 {
		return fmt.Errorf("daemon parse timeout must be greater than zero")
	}
	if config.ImportTimeout <= 0 {
		return fmt.Errorf("daemon import timeout must be greater than zero")
	}
	name := strings.TrimSpace(config.ImporterWhoName)
	if name == "" {
		return fmt.Errorf("daemon importer who name is required")
	}

	slog.Info("starting pmgbot daemon",
		"before", config.Before.String(),
		"every", config.Every.String(),
		"parse_timeout", config.ParseTimeout.String(),
		"importer_who_name", name,
		"import_timeout", config.ImportTimeout.String(),
	)

	for {
		if err := runDaemonOnce(ctx, config); err != nil {
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

func runDaemonOnce(ctx context.Context, config DaemonConfig) error {
	parseCtx, cancel := context.WithTimeout(ctx, config.ParseTimeout)
	senders, err := collectDeletedSpamSenders(parseCtx, config.Before)
	cancel()
	if err != nil {
		return err
	}
	slog.Info("daemon deleted spam senders collected", "count", len(senders))
	if len(senders) == 0 {
		return nil
	}

	importCtx, cancel := context.WithTimeout(ctx, config.ImportTimeout)
	id, err := ImportEmailsContext(importCtx, senders, ImporterConfig{
		WhoName: strings.TrimSpace(config.ImporterWhoName),
		Timeout: config.ImportTimeout,
	})
	cancel()
	if err != nil {
		return err
	}
	slog.Info("daemon deleted spam senders imported", "id", id, "count", len(senders))

	return nil
}
