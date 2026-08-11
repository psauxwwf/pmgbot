package pmg

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"pmgbot/pkg/cmd"
)

const quarantineSpamLookbackDays = 30

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
