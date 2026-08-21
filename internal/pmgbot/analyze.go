package pmgbot

import (
	"context"
	"fmt"
	"io"
	"sort"

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
	Count          int
	Action         string
}

type spamAnalysisSenderKey struct {
	EnvelopeSender string
	From           string
	Action         string
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

	return writeSpamAnalysis(output, analyzeSpamMessages(messages, minCount, rules))
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

	return writeSpamAnalysis(output, analyzeSpamMessages(messages, minCount, rules))
}

func writeSpamAnalysis(output io.Writer, rows []spamAnalysisRow) error {
	for i, row := range rows {
		if _, err := fmt.Fprintf(output, "%s - %d - %s - %s\n", row.Subject, row.Count, row.Script, row.Language); err != nil {
			return fmt.Errorf("write spam analysis: %w", err)
		}
		for _, sender := range row.Senders {
			if _, err := fmt.Fprintf(output, "%s - %s - %d - %s\n", sender.EnvelopeSender, sender.From, sender.Count, sender.Action); err != nil {
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

func analyzeSpamMessages(messages []quarantineSpamMessage, minCount int, rules []compiledRule) []spamAnalysisRow {
	if minCount <= 0 {
		minCount = 1
	}

	countsBySubject := make(map[string]map[spamAnalysisSenderKey]int)
	for _, message := range messages {
		if countsBySubject[message.Subject] == nil {
			countsBySubject[message.Subject] = make(map[spamAnalysisSenderKey]int)
		}
		key := spamAnalysisSenderKey{
			EnvelopeSender: message.EnvelopeSender,
			From:           message.From,
			Action:         spamAnalysisMessageAction(message, rules),
		}
		countsBySubject[message.Subject][key]++
	}

	rows := make([]spamAnalysisRow, 0, len(countsBySubject))
	for subject, senderCounts := range countsBySubject {
		row := spamAnalysisRow{
			Subject:  subject,
			Script:   lang.SubjectScript(subject),
			Language: lang.SubjectLanguage(subject),
		}
		for sender, count := range senderCounts {
			row.Count += count
			row.Senders = append(row.Senders, spamAnalysisSenderRow{
				EnvelopeSender: sender.EnvelopeSender,
				From:           sender.From,
				Count:          count,
				Action:         sender.Action,
			})
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

func spamAnalysisMessageAction(message quarantineSpamMessage, rules []compiledRule) string {
	action, _, ok := decideQuarantineAction(message, rules)
	if !ok {
		return "skip"
	}

	return string(action)
}
