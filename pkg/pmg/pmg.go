package pmg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pmgbot/pkg/cmd"
)

const (
	quarantineSpamLookbackDays = 30
	quarantineSpoolRoot        = "/var/spool/pmg"
)

type SpamMessage struct {
	Bytes          int64  `json:"bytes"`
	EnvelopeSender string `json:"envelope_sender"`
	From           string `json:"from"`
	ID             string `json:"id"`
	Receiver       string `json:"receiver"`
	SpamLevel      int64  `json:"spamlevel"`
	Subject        string `json:"subject"`
	Time           int64  `json:"time"`
}

type SpamContent struct {
	Bytes          int64      `json:"bytes"`
	Content        string     `json:"content"`
	EnvelopeSender string     `json:"envelope_sender"`
	File           string     `json:"file"`
	From           string     `json:"from"`
	Header         string     `json:"header"`
	ID             string     `json:"id"`
	Receiver       string     `json:"receiver"`
	SpamInfo       []SpamInfo `json:"spaminfo"`
	SpamLevel      int64      `json:"spamlevel"`
	Subject        string     `json:"subject"`
	Time           int64      `json:"time"`
	Raw            string     `json:"raw"`
}

type SpamInfo struct {
	Desc  string  `json:"desc"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

func QuarantineSpam(ctx context.Context) ([]SpamMessage, error) {
	pmgshCmd, cancel, err := cmd.NewContext(ctx, "pmgsh", quarantineSpamArgs(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("create pmgsh quarantine spam command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		return nil, pmgshError("pmgsh quarantine spam failed", err, out)
	}

	return quarantineSpamFromOutput(out)
}

func quarantineSpamArgs(now time.Time) []string {
	endtime := now.Unix()
	starttime := now.AddDate(0, 0, -quarantineSpamLookbackDays).Unix()

	return []string{
		"get",
		"/quarantine/spam",
		"--starttime",
		strconv.FormatInt(starttime, 10),
		"--endtime",
		strconv.FormatInt(endtime, 10),
	}
}

func ApplyQuarantineAction(ctx context.Context, id string, action string) ([]byte, error) {
	pmgshCmd, cancel, err := cmd.NewContext(
		ctx,
		"pmgsh",
		[]string{"create", "/quarantine/content", "--id", id, "--action", action},
	)
	if err != nil {
		return nil, fmt.Errorf("create pmgsh quarantine action command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		return nil, pmgshError(fmt.Sprintf("pmgsh quarantine %s %q failed", action, id), err, out)
	}

	return out, nil
}

func QuarantineContent(ctx context.Context, id string) (SpamContent, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return SpamContent{}, fmt.Errorf("quarantine content id is empty")
	}

	pmgshCmd, cancel, err := cmd.NewContext(
		ctx,
		"pmgsh",
		[]string{"get", "/quarantine/content", "--id", id},
	)
	if err != nil {
		return SpamContent{}, fmt.Errorf("create pmgsh quarantine content command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		return SpamContent{}, pmgshError(fmt.Sprintf("pmgsh quarantine content %q failed", id), err, out)
	}

	content, err := quarantineContentFromOutput(out)
	if err != nil {
		return SpamContent{}, err
	}
	raw, err := quarantineRawFromFile(quarantineSpoolRoot, content.File)
	if err != nil {
		return SpamContent{}, err
	}
	content.Raw = raw

	return content, nil
}

func pmgshError(message string, err error, out []byte) error {
	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("%s: %w: %s", message, err, strings.TrimSpace(string(out)))
	}

	return fmt.Errorf("%s: %w", message, err)
}

func quarantineSpamFromOutput(out []byte) ([]SpamMessage, error) {
	var messages []SpamMessage
	if err := decodeJSONArray(out, &messages); err != nil {
		return nil, fmt.Errorf("parse pmgsh quarantine spam output: %w", err)
	}

	return messages, nil
}

func quarantineContentFromOutput(out []byte) (SpamContent, error) {
	var content SpamContent
	if err := decodeJSONObject(out, &content); err != nil {
		return SpamContent{}, fmt.Errorf("parse pmgsh quarantine content output: %w", err)
	}

	return content, nil
}

func quarantineRawFromFile(root string, file string) (string, error) {
	rel := strings.TrimSpace(file)
	if rel == "" {
		return "", fmt.Errorf("quarantine content file is empty")
	}

	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid quarantine content file %q", file)
	}

	path := filepath.Join(root, clean)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read quarantine raw content %s: %w", path, err)
	}

	return string(data), nil
}

func decodeJSONArray(out []byte, v any) error {
	text := strings.TrimSpace(string(out))
	jsonStart := strings.Index(text, "[")
	if jsonStart == -1 {
		return fmt.Errorf("pmgsh output does not contain JSON array")
	}

	decoder := json.NewDecoder(strings.NewReader(text[jsonStart:]))
	if err := decoder.Decode(v); err != nil {
		return err
	}

	return nil
}

func decodeJSONObject(out []byte, v any) error {
	text := strings.TrimSpace(string(out))
	jsonStart := strings.Index(text, "{")
	if jsonStart == -1 {
		return fmt.Errorf("pmgsh output does not contain JSON object")
	}

	decoder := json.NewDecoder(strings.NewReader(text[jsonStart:]))
	if err := decoder.Decode(v); err != nil {
		return err
	}

	return nil
}
