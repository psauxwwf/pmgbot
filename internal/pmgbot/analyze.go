package pmgbot

import (
	"context"
	"fmt"
	"io"
	"sort"
)

type spamAnalysisRow struct {
	Subject string
	Count   int
	Senders []spamAnalysisSenderRow
}

type spamAnalysisSenderRow struct {
	EnvelopeSender string
	Count          int
}

func Analyze(ctx context.Context, config DaemonConfig, minCount int, output io.Writer) error {
	return analyze(ctx, config, minCount, output, pmgQuarantineSpamContext)
}

func AnalyzeSpamJSON(_ context.Context, config DaemonConfig, path string, minCount int, output io.Writer) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}

	messages, err := readSpamMessagesJSON(path)
	if err != nil {
		return err
	}

	return writeSpamAnalysis(output, analyzeSpamMessages(messages, minCount))
}

func analyze(ctx context.Context, config DaemonConfig, minCount int, output io.Writer, quarantineSpam quarantineSpamFunc) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}

	cycleCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	messages, err := quarantineSpam(cycleCtx)
	cancel()
	if err != nil {
		return err
	}

	return writeSpamAnalysis(output, analyzeSpamMessages(messages, minCount))
}

func writeSpamAnalysis(output io.Writer, rows []spamAnalysisRow) error {
	for i, row := range rows {
		if _, err := fmt.Fprintf(output, "%s - %d\n", row.Subject, row.Count); err != nil {
			return fmt.Errorf("write spam analysis: %w", err)
		}
		for _, sender := range row.Senders {
			if _, err := fmt.Fprintf(output, "%s - %d\n", sender.EnvelopeSender, sender.Count); err != nil {
				return fmt.Errorf("write spam analysis: %w", err)
			}
		}
		if i < len(rows)-1 {
			if _, err := fmt.Fprintln(output, "---"); err != nil {
				return fmt.Errorf("write spam analysis: %w", err)
			}
		}
	}

	return nil
}

func analyzeSpamMessages(messages []quarantineSpamMessage, minCount int) []spamAnalysisRow {
	if minCount <= 0 {
		minCount = 1
	}

	countsBySubject := make(map[string]map[string]int)
	for _, message := range messages {
		if countsBySubject[message.Subject] == nil {
			countsBySubject[message.Subject] = make(map[string]int)
		}
		countsBySubject[message.Subject][message.EnvelopeSender]++
	}

	rows := make([]spamAnalysisRow, 0, len(countsBySubject))
	for subject, senderCounts := range countsBySubject {
		row := spamAnalysisRow{Subject: subject}
		for sender, count := range senderCounts {
			row.Count += count
			row.Senders = append(row.Senders, spamAnalysisSenderRow{
				EnvelopeSender: sender,
				Count:          count,
			})
		}
		if row.Count < minCount {
			continue
		}
		sort.Slice(row.Senders, func(i, j int) bool {
			if row.Senders[i].Count != row.Senders[j].Count {
				return row.Senders[i].Count > row.Senders[j].Count
			}

			return row.Senders[i].EnvelopeSender < row.Senders[j].EnvelopeSender
		})
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}

		return rows[i].Subject < rows[j].Subject
	})

	return rows
}
