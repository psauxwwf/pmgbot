package pmgbot

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"pmgbot/pkg/lang"
)

type spamAnalysisRow struct {
	Subject  string
	Count    int
	Script   string
	Language string
	Senders  []spamAnalysisSenderRow
}

type spamAnalysisSenderRow struct {
	EnvelopeSender string
	From           string
	IDs            []string
	Count          int
	Action         string
}

type spamAnalysisSenderKey struct {
	EnvelopeSender string
	From           string
	Action         string
}

type spamAnalysisSummary struct {
	Total   int
	Deliver int
	Delete  int
	Remain  int
}

func Analyze(ctx context.Context, config DaemonConfig, minCount int, output io.Writer) error {
	return analyze(ctx, config, minCount, output, pmgQuarantineSpamContext)
}

func AnalyzeSpamJSON(_ context.Context, config DaemonConfig, path string, minCount int, output io.Writer) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	messages, err := readSpamMessagesJSON(path)
	if err != nil {
		return err
	}

	return writeSpamAnalysis(output, analyzeSpamMessages(messages, minCount, rules), analyzeSpamSummary(messages, rules))
}

func analyze(ctx context.Context, config DaemonConfig, minCount int, output io.Writer, quarantineSpam quarantineSpamFunc) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}
	rules, err := compileDaemonRules(config)
	if err != nil {
		return err
	}

	cycleCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	messages, err := quarantineSpam(cycleCtx)
	cancel()
	if err != nil {
		return err
	}

	return writeSpamAnalysis(output, analyzeSpamMessages(messages, minCount, rules), analyzeSpamSummary(messages, rules))
}

func writeSpamAnalysis(output io.Writer, rows []spamAnalysisRow, summary spamAnalysisSummary) error {
	for i, row := range rows {
		if _, err := fmt.Fprintf(output, "%s | %d | %s | %s\n", row.Subject, row.Count, row.Script, row.Language); err != nil {
			return fmt.Errorf("write spam analysis: %w", err)
		}
		for _, sender := range row.Senders {
			if _, err := fmt.Fprintf(output, "%s | %s | %s | %d | %s\n", sender.EnvelopeSender, sender.From, sender.IDText(), sender.Count, sender.Action); err != nil {
				return fmt.Errorf("write spam analysis: %w", err)
			}
		}
		if i < len(rows)-1 {
			if _, err := fmt.Fprintln(output, "---"); err != nil {
				return fmt.Errorf("write spam analysis: %w", err)
			}
		}
	}
	if len(rows) > 0 {
		if _, err := fmt.Fprintln(output, "---"); err != nil {
			return fmt.Errorf("write spam analysis: %w", err)
		}
	}
	if _, err := fmt.Fprintf(output, "summary | total: %d | deliver: %d | delete: %d | remain: %d\n", summary.Total, summary.Deliver, summary.Delete, summary.Remain); err != nil {
		return fmt.Errorf("write spam analysis: %w", err)
	}

	return nil
}

func (row spamAnalysisSenderRow) IDText() string {
	if len(row.IDs) == 0 {
		return "-"
	}

	return "[" + strings.Join(row.IDs, ",") + "]"
}

func analyzeSpamSummary(messages []quarantineSpamMessage, rules []compiledRule) spamAnalysisSummary {
	summary := spamAnalysisSummary{Total: len(messages)}
	for _, message := range messages {
		action, _, ok := decideQuarantineActionForMessages(message, messages, rules)
		if !ok {
			summary.Remain++
			continue
		}

		switch action {
		case quarantineActionDeliver:
			summary.Deliver++
		case quarantineActionDelete:
			summary.Delete++
		default:
			summary.Remain++
		}
	}

	return summary
}

func analyzeSpamMessages(messages []quarantineSpamMessage, minCount int, rules []compiledRule) []spamAnalysisRow {
	if minCount <= 0 {
		minCount = 1
	}

	countsBySubject := make(map[string]map[spamAnalysisSenderKey]spamAnalysisSenderRow)
	for _, message := range messages {
		if countsBySubject[message.Subject] == nil {
			countsBySubject[message.Subject] = make(map[spamAnalysisSenderKey]spamAnalysisSenderRow)
		}
		key := spamAnalysisSenderKey{
			EnvelopeSender: message.EnvelopeSender,
			From:           message.From,
			Action:         spamAnalysisMessageAction(message, messages, rules),
		}
		sender := countsBySubject[message.Subject][key]
		sender.EnvelopeSender = key.EnvelopeSender
		sender.From = key.From
		sender.Action = key.Action
		sender.Count++
		if id := strings.TrimSpace(message.ID); id != "" {
			sender.IDs = append(sender.IDs, id)
		}
		countsBySubject[message.Subject][key] = sender
	}

	rows := make([]spamAnalysisRow, 0, len(countsBySubject))
	for subject, senderCounts := range countsBySubject {
		row := spamAnalysisRow{
			Subject:  subject,
			Script:   lang.SubjectScript(subject),
			Language: lang.SubjectLanguage(subject),
		}
		for _, sender := range senderCounts {
			row.Count += sender.Count
			row.Senders = append(row.Senders, sender)
		}
		if row.Count < minCount {
			continue
		}
		sort.Slice(row.Senders, func(i, j int) bool {
			if row.Senders[i].Count != row.Senders[j].Count {
				return row.Senders[i].Count > row.Senders[j].Count
			}
			if row.Senders[i].EnvelopeSender != row.Senders[j].EnvelopeSender {
				return row.Senders[i].EnvelopeSender < row.Senders[j].EnvelopeSender
			}
			if row.Senders[i].From != row.Senders[j].From {
				return row.Senders[i].From < row.Senders[j].From
			}

			return row.Senders[i].Action < row.Senders[j].Action
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

func spamAnalysisMessageAction(message quarantineSpamMessage, messages []quarantineSpamMessage, rules []compiledRule) string {
	action, ruleName, ok := decideQuarantineActionForMessages(message, messages, rules)
	if !ok {
		return "skip"
	}

	return fmt.Sprintf("[%s:%s]", action, ruleName)
}
