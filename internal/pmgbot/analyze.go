package pmgbot

import (
	"context"
	"fmt"
	"io"
	"sort"
)

type spamAnalysisRow struct {
	EnvelopeSender string
	Subject        string
	Count          int
}

type spamAnalysisKey struct {
	EnvelopeSender string
	Subject        string
}

func Analyze(ctx context.Context, config DaemonConfig, output io.Writer) error {
	return analyze(ctx, config, output, pmgQuarantineSpamContext)
}

func analyze(ctx context.Context, config DaemonConfig, output io.Writer, quarantineSpam quarantineSpamFunc) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}

	cycleCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	messages, err := quarantineSpam(cycleCtx)
	cancel()
	if err != nil {
		return err
	}

	for _, row := range analyzeSpamMessages(messages) {
		if _, err := fmt.Fprintf(output, "%s - %s - %d\n", row.EnvelopeSender, row.Subject, row.Count); err != nil {
			return fmt.Errorf("write spam analysis: %w", err)
		}
	}

	return nil
}

func analyzeSpamMessages(messages []quarantineSpamMessage) []spamAnalysisRow {
	counts := make(map[spamAnalysisKey]int)
	for _, message := range messages {
		key := spamAnalysisKey{
			EnvelopeSender: message.EnvelopeSender,
			Subject:        message.Subject,
		}
		counts[key]++
	}

	rows := make([]spamAnalysisRow, 0, len(counts))
	for key, count := range counts {
		rows = append(rows, spamAnalysisRow{
			EnvelopeSender: key.EnvelopeSender,
			Subject:        key.Subject,
			Count:          count,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if rows[i].EnvelopeSender != rows[j].EnvelopeSender {
			return rows[i].EnvelopeSender < rows[j].EnvelopeSender
		}

		return rows[i].Subject < rows[j].Subject
	})

	return rows
}
