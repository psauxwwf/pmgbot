package pmgbot

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"pmgbot/pkg/lang"
)

type daemonReportCountRow struct {
	Name  string
	Count int
}

type daemonReportRuleRow struct {
	Rule      string
	Action    quarantineAction
	Count     int
	Delivered int
	Deleted   int
	Errors    int
}

type daemonReportSubjectRow struct {
	Subject  string
	Count    int
	Script   string
	Language string
}

var daemonReportNow = time.Now

func WriteDaemonMarkdownReport(mode string, report daemonCycleReport) (string, error) {
	generatedAt := daemonReportNow()
	path := daemonMarkdownReportPath(mode, generatedAt)

	var out strings.Builder
	writeDaemonMarkdownReport(&out, mode, generatedAt, report)
	if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
		return "", fmt.Errorf("write daemon markdown report %s: %w", path, err)
	}

	return path, nil
}

func daemonMarkdownReportPath(mode string, generatedAt time.Time) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "daemon"
	}

	return fmt.Sprintf("pmgbot-%s-report-%s-%09d.md", mode, generatedAt.Format("20060102-150405"), generatedAt.Nanosecond())
}

func writeDaemonMarkdownReport(out *strings.Builder, mode string, generatedAt time.Time, report daemonCycleReport) {
	matched := report.Delivered + report.Deleted + report.Errors
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "daemon"
	}

	fmt.Fprintf(out, "# pmgbot %s report\n\n", mode)
	fmt.Fprintf(out, "Generated at: `%s`\n\n", generatedAt.Format(time.RFC3339))

	out.WriteString("## Summary\n\n")
	writeMarkdownKeyValueTable(out, [][2]string{
		{"mode", mode},
		{"dry_run", fmt.Sprintf("%t", report.DryRun)},
		{"total", fmt.Sprintf("%d", report.Total)},
		{"matched", fmt.Sprintf("%d", matched)},
		{"delivered", fmt.Sprintf("%d", report.Delivered)},
		{"deleted", fmt.Sprintf("%d", report.Deleted)},
		{"skipped", fmt.Sprintf("%d", report.Skipped)},
		{"errors", fmt.Sprintf("%d", report.Errors)},
		{"action_rows", fmt.Sprintf("%d", len(report.Actions))},
	})

	out.WriteString("## Action Metrics\n\n")
	writeMarkdownKeyValueTable(out, [][2]string{
		{"deliver_success_or_planned", fmt.Sprintf("%d", report.Delivered)},
		{"delete_success_or_planned", fmt.Sprintf("%d", report.Deleted)},
		{"action_errors", fmt.Sprintf("%d", report.Errors)},
		{"without_matching_rule", fmt.Sprintf("%d", report.Skipped)},
	})

	writeRuleMetrics(out, report)
	writeCountMetrics(out, "Receiver Metrics", countMessagesByField(report, "receiver"))
	writeCountMetrics(out, "Envelope Sender Metrics", countMessagesByField(report, "envelope_sender"))
	writeCountMetrics(out, "From Header Metrics", countMessagesByField(report, "from"))
	writeSubjectMetrics(out, report)
	writeSkippedMessages(out, report.SkippedMessages)
	writeActionRows(out, report)
}

func writeMarkdownKeyValueTable(out *strings.Builder, rows [][2]string) {
	out.WriteString("| metric | value |\n")
	out.WriteString("| --- | --- |\n")
	for _, row := range rows {
		fmt.Fprintf(out, "| %s | %s |\n", markdownCell(row[0]), markdownCell(row[1]))
	}
	out.WriteString("\n")
}

func writeRuleMetrics(out *strings.Builder, report daemonCycleReport) {
	rowsByKey := make(map[string]daemonReportRuleRow)
	for _, action := range report.Actions {
		key := string(action.Action) + "\x00" + action.RuleName
		row := rowsByKey[key]
		row.Rule = action.RuleName
		row.Action = action.Action
		row.Count++
		if action.Error != nil {
			row.Errors++
		} else if action.Action == quarantineActionDeliver {
			row.Delivered++
		} else if action.Action == quarantineActionDelete {
			row.Deleted++
		}
		rowsByKey[key] = row
	}

	rows := make([]daemonReportRuleRow, 0, len(rowsByKey))
	for _, row := range rowsByKey {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		if rows[i].Action != rows[j].Action {
			return rows[i].Action < rows[j].Action
		}

		return rows[i].Rule < rows[j].Rule
	})

	out.WriteString("## Rule Metrics\n\n")
	if len(rows) == 0 {
		out.WriteString("No rule actions.\n\n")
		return
	}
	out.WriteString("| action | rule | count | delivered | deleted | errors |\n")
	out.WriteString("| --- | --- | ---: | ---: | ---: | ---: |\n")
	for _, row := range rows {
		fmt.Fprintf(
			out,
			"| %s | %s | %d | %d | %d | %d |\n",
			markdownCell(string(row.Action)),
			markdownCell(row.Rule),
			row.Count,
			row.Delivered,
			row.Deleted,
			row.Errors,
		)
	}
	out.WriteString("\n")
}

func writeCountMetrics(out *strings.Builder, title string, counts map[string]int) {
	rows := sortedCountRows(counts)
	fmt.Fprintf(out, "## %s\n\n", title)
	if len(rows) == 0 {
		out.WriteString("No data.\n\n")
		return
	}
	out.WriteString("| value | count |\n")
	out.WriteString("| --- | ---: |\n")
	for _, row := range rows {
		fmt.Fprintf(out, "| %s | %d |\n", markdownCell(row.Name), row.Count)
	}
	out.WriteString("\n")
}

func writeSubjectMetrics(out *strings.Builder, report daemonCycleReport) {
	counts := make(map[string]int)
	for _, action := range report.Actions {
		counts[action.Message.Subject]++
	}
	for _, message := range report.SkippedMessages {
		counts[message.Subject]++
	}

	rows := make([]daemonReportSubjectRow, 0, len(counts))
	for subject, count := range counts {
		rows = append(rows, daemonReportSubjectRow{
			Subject:  subject,
			Count:    count,
			Script:   lang.SubjectScript(subject),
			Language: lang.SubjectLanguage(subject),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}

		return rows[i].Subject < rows[j].Subject
	})

	out.WriteString("## Subject Metrics\n\n")
	if len(rows) == 0 {
		out.WriteString("No data.\n\n")
		return
	}
	out.WriteString("| subject | count | script | language |\n")
	out.WriteString("| --- | ---: | --- | --- |\n")
	for _, row := range rows {
		fmt.Fprintf(out, "| %s | %d | %s | %s |\n", markdownCell(row.Subject), row.Count, markdownCell(row.Script), markdownCell(row.Language))
	}
	out.WriteString("\n")
}

func writeSkippedMessages(out *strings.Builder, messages []quarantineSpamMessage) {
	out.WriteString("## Skipped Messages\n\n")
	if len(messages) == 0 {
		out.WriteString("No skipped messages.\n\n")
		return
	}
	out.WriteString("| id | subject | envelope_sender | from | receiver | spamlevel | bytes | time |\n")
	out.WriteString("| --- | --- | --- | --- | --- | ---: | ---: | --- |\n")
	for _, message := range messages {
		fmt.Fprintf(
			out,
			"| %s | %s | %s | %s | %s | %d | %d | %s |\n",
			markdownCell(message.ID),
			markdownCell(message.Subject),
			markdownCell(message.EnvelopeSender),
			markdownCell(message.From),
			markdownCell(message.Receiver),
			message.SpamLevel,
			message.Bytes,
			markdownCell(messageTimeText(message.Time)),
		)
	}
	out.WriteString("\n")
}

func writeActionRows(out *strings.Builder, report daemonCycleReport) {
	out.WriteString("## Actions\n\n")
	if len(report.Actions) == 0 {
		out.WriteString("No deliver/delete actions.\n")
		return
	}
	out.WriteString("| index | result | action | rule | id | subject | envelope_sender | from | receiver | spamlevel | bytes | time | error |\n")
	out.WriteString("| ---: | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |\n")
	for i, action := range report.Actions {
		fmt.Fprintf(
			out,
			"| %d | %s | %s | %s | %s | %s | %s | %s | %s | %d | %d | %s | %s |\n",
			i+1,
			markdownCell(actionResultText(report.DryRun, action)),
			markdownCell(string(action.Action)),
			markdownCell(action.RuleName),
			markdownCell(daemonCycleActionID(action.ID)),
			markdownCell(action.Message.Subject),
			markdownCell(action.Message.EnvelopeSender),
			markdownCell(action.Message.From),
			markdownCell(action.Message.Receiver),
			action.Message.SpamLevel,
			action.Message.Bytes,
			markdownCell(messageTimeText(action.Message.Time)),
			markdownCell(errorText(action.Error)),
		)
	}
}

func countMessagesByField(report daemonCycleReport, field string) map[string]int {
	counts := make(map[string]int)
	for _, action := range report.Actions {
		incrementMessageFieldCount(counts, action.Message, field)
	}
	for _, message := range report.SkippedMessages {
		incrementMessageFieldCount(counts, message, field)
	}

	return counts
}

func incrementMessageFieldCount(counts map[string]int, message quarantineSpamMessage, field string) {
	value, ok := quarantineMessageFieldString(message, field)
	if !ok {
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = "-"
	}
	counts[value]++
}

func sortedCountRows(counts map[string]int) []daemonReportCountRow {
	rows := make([]daemonReportCountRow, 0, len(counts))
	for name, count := range counts {
		rows = append(rows, daemonReportCountRow{Name: name, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}

		return rows[i].Name < rows[j].Name
	})

	return rows
}

func actionResultText(dryRun bool, action daemonCycleActionRow) string {
	if action.Error != nil {
		return "error"
	}
	if dryRun {
		return "planned"
	}

	return "applied"
}

func errorText(err error) string {
	if err == nil {
		return "-"
	}

	return err.Error()
}

func messageTimeText(unixTime int64) string {
	if unixTime <= 0 {
		return "-"
	}

	return time.Unix(unixTime, 0).Format(time.RFC3339)
}

func markdownCell(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	replacer := strings.NewReplacer(
		"|", `\|`,
		"\r\n", "<br>",
		"\n", "<br>",
		"\r", "<br>",
	)

	return replacer.Replace(value)
}
