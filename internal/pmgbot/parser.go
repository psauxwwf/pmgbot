package pmgbot

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"pmgbot/pkg/cmd"
	"pmgbot/pkg/fs"
)

const (
	maxDebugJournalSamples = 10
	maxDebugCandidateLines = 20
	journalSinceLayout     = "2006-01-02 15:04:05"
)

var (
	spamPathRE = regexp.MustCompile(`(?i)/var/spool/pmg/cluster/[0-9]+/spam/[a-f0-9]{2}/[a-f0-9]+`)
	emailRE    = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)
)

func Parse(config ParserConfig) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("parser timeout must be greater than zero")
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	return ParseContext(ctx, config)
}

func ParseContext(ctx context.Context, config ParserConfig) error {
	if config.Before <= 0 {
		return fmt.Errorf("parser before must be greater than zero")
	}
	since := sinceFromBefore(time.Now(), config.Before)
	slog.Info("starting pmgbot parser",
		"before", config.Before.String(),
		"since", since,
		"blacklist", config.Blacklist,
		"parse_timeout", config.Timeout.String(),
	)
	existingSenders, err := existingBlacklistSenders(config.Blacklist)
	if err != nil {
		return err
	}
	slog.Info("existing blacklist senders loaded", "blacklist", config.Blacklist, "count", len(existingSenders))

	senders, err := collectDeletedSpamSenders(ctx, config.Before)
	if err != nil {
		return err
	}
	senders = appendUniqueSenders(existingSenders, senders)
	slog.Info("merged deleted spam senders with existing blacklist", "blacklist", config.Blacklist, "count", len(senders))
	excludedSenders, err := readEmailList(config.Exclude)
	if err != nil {
		return err
	}
	senders, err = excludeEmails(senders, excludedSenders)
	if err != nil {
		return err
	}
	slog.Info("excluded senders filtered from blacklist", "exclude", config.Exclude, "excluded_count", len(excludedSenders), "count", len(senders))

	if err := fs.WriteLines(config.Blacklist, senders); err != nil {
		return fmt.Errorf("write %s: %w", config.Blacklist, err)
	}
	slog.Info("deleted spam senders written", "blacklist", config.Blacklist, "count", len(senders))

	return nil
}

func collectDeletedSpamSenders(ctx context.Context, before time.Duration) ([]string, error) {
	since := sinceFromBefore(time.Now(), before)
	paths, err := deletedSpamPaths(
		ctx,
		since,
	)
	if err != nil {
		return nil, err
	}
	slog.Info("deleted spam paths found", "count", len(paths))
	if len(paths) == 0 {
		slog.Debug("no deleted spam paths found; blacklist will be empty unless journalctl query or path regexp changes")
	}

	senders, err := deletedSpamSenders(paths)
	if err != nil {
		return nil, err
	}
	slog.Info("deleted spam senders found", "count", len(senders))
	if len(paths) > 0 && len(senders) == 0 {
		slog.Debug("deleted spam paths were found but no senders were extracted; check missing files and header extraction logs")
	}

	return senders, nil
}

func sinceFromBefore(now time.Time, before time.Duration) string {
	return now.Add(-before).Format(journalSinceLayout)
}

func existingBlacklistSenders(path string) ([]string, error) {
	return readEmailList(path)
}

func readEmailList(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	exists, err := fs.ExistsFile(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}

	file, err := fs.OpenReadFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var senders []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sender := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if sender != "" && !slices.Contains(senders, sender) {
			senders = append(senders, sender)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read email list %s: %w", path, err)
	}

	return senders, nil
}

func appendUniqueSenders(existing, next []string) []string {
	senders := slices.Clone(existing)
	for _, sender := range next {
		sender = strings.ToLower(strings.TrimSpace(sender))
		if sender != "" && !slices.Contains(senders, sender) {
			senders = append(senders, sender)
		}
	}

	return senders
}

func deletedSpamPaths(ctx context.Context, since string) ([]string, error) {
	slog.Debug("running journalctl",
		"units", []string{"pmgproxy", "pmgdaemon"},
		"since", since,
	)

	journalCmd, cancel, err := cmd.NewContext(
		ctx,
		"journalctl",
		[]string{"-u", "pmgproxy", "-u", "pmgdaemon", "--since", since},
	)
	if err != nil {
		return nil, fmt.Errorf("create journalctl command: %w", err)
	}
	defer cancel()

	out, err := journalCmd.Run()
	if err != nil {
		if strings.TrimSpace(string(out)) != "" {
			return nil, fmt.Errorf("journalctl failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil, fmt.Errorf("journalctl failed: %w", err)
	}
	slog.Debug("journalctl completed", "bytes", len(out))

	paths, err := scanDeletedSpamPaths(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)

	return paths, nil
}

func scanDeletedSpamPaths(r io.Reader) ([]string, error) {
	var (
		paths            []string
		journalSamples   []string
		candidateLines   []string
		lineCount        int
		deletedLineCount int
		matchedLineCount int
		matchCount       int
		duplicateCount   int
	)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()
		if len(journalSamples) < maxDebugJournalSamples {
			journalSamples = append(journalSamples, line)
		}

		lower := strings.ToLower(line)
		if strings.Contains(lower, "delete") || strings.Contains(lower, "spam") || strings.Contains(lower, "/var/spool/pmg") {
			if len(candidateLines) < maxDebugCandidateLines {
				candidateLines = append(candidateLines, line)
			}
		}

		if !strings.Contains(line, "as deleted") {
			continue
		}
		deletedLineCount++

		matches := spamPathRE.FindAllString(line, -1)
		if len(matches) == 0 {
			slog.Debug("deleted journal line has no matching spam path", "line_number", lineCount, "line", line)
			continue
		}
		matchedLineCount++

		for _, match := range matches {
			matchCount++
			if !slices.Contains(paths, match) {
				paths = append(paths, match)
				slog.Debug("deleted spam path found", "path", match, "line_number", lineCount)
				continue
			}

			duplicateCount++
			slog.Debug("duplicate deleted spam path ignored", "path", match, "line_number", lineCount)
		}
	}

	slog.Debug("journalctl scan finished",
		"lines", lineCount,
		"deleted_lines", deletedLineCount,
		"matched_lines", matchedLineCount,
		"path_matches", matchCount,
		"duplicates", duplicateCount,
		"unique_paths", len(paths),
	)
	if deletedLineCount == 0 {
		slog.Debug("journalctl had no exact 'as deleted' lines",
			"sample_limit", maxDebugJournalSamples,
			"samples", journalSamples,
			"candidate_limit", maxDebugCandidateLines,
			"candidates", candidateLines,
		)
	}

	return paths, scanner.Err()
}

func deletedSpamSenders(paths []string) ([]string, error) {
	var (
		senders        []string
		checkedFiles   int
		missingFiles   int
		noSenderFiles  int
		duplicateFiles int
	)

	for _, path := range paths {
		slog.Debug("checking deleted spam file", "path", path)

		exists, err := fs.ExistsFile(path)
		if err != nil {
			return nil, err
		}
		if !exists {
			missingFiles++
			slog.Debug("skipping missing spam file", "path", path)
			continue
		}
		checkedFiles++

		sender, err := senderFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("read sender from %s: %w", path, err)
		}
		if sender == "" {
			noSenderFiles++
			slog.Debug("no sender extracted from spam file", "path", path)
			continue
		}

		sender = strings.ToLower(sender)
		if slices.Contains(senders, sender) {
			duplicateFiles++
			slog.Debug("duplicate sender ignored", "path", path, "sender", sender)
			continue
		}

		senders = append(senders, sender)
		slog.Debug("sender added", "path", path, "sender", sender)
	}

	slices.Sort(senders)
	slog.Debug("sender scan finished",
		"paths", len(paths),
		"checked_files", checkedFiles,
		"missing_files", missingFiles,
		"no_sender_files", noSenderFiles,
		"duplicate_sender_files", duplicateFiles,
		"unique_senders", len(senders),
	)

	return senders, nil
}

func senderFromFile(path string) (string, error) {
	file, err := fs.OpenReadFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var (
		returnPath     string
		from           string
		seenReturnPath bool
		seenFrom       bool
	)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		lower := strings.ToLower(line)

		if !seenReturnPath && strings.HasPrefix(lower, "return-path:") {
			seenReturnPath = true
			returnPath = firstEmail(line)
			slog.Debug("return-path header scanned",
				"path", path,
				"line_number", lineNumber,
				"email", returnPath,
				"has_email", returnPath != "",
			)
		}

		if !seenFrom && strings.HasPrefix(lower, "from:") {
			seenFrom = true
			from = firstEmail(line)
			slog.Debug("from header scanned",
				"path", path,
				"line_number", lineNumber,
				"email", from,
				"has_email", from != "",
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	if returnPath != "" {
		slog.Debug("sender selected from return-path", "path", path, "sender", returnPath)
		return returnPath, nil
	}
	if from != "" {
		slog.Debug("sender selected from from header", "path", path, "sender", from)
		return from, nil
	}

	slog.Debug("sender headers did not contain email",
		"path", path,
		"lines", lineNumber,
		"seen_return_path", seenReturnPath,
		"seen_from", seenFrom,
	)

	return from, nil
}

func firstEmail(s string) string {
	return emailRE.FindString(s)
}
