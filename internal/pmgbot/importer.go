package pmgbot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"pmgbot/pkg/cmd"
)

type pmgWho struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type pmgWhoObject struct {
	ID           int    `json:"id"`
	OGroup       int    `json:"ogroup"`
	OType        int    `json:"otype"`
	OTypeText    string `json:"otype_text"`
	Email        string `json:"email"`
	Descr        string `json:"descr"`
	ReceiverTest int    `json:"receivertest"`
}

func Import(config ImporterConfig) (int, error) {
	if config.Timeout <= 0 {
		return 0, fmt.Errorf("import timeout must be greater than zero")
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	return ImportContext(ctx, config)
}

func ImportContext(ctx context.Context, config ImporterConfig) (int, error) {
	slog.Info("starting pmgbot importer", "who_name", strings.TrimSpace(config.WhoName), "blacklist", config.Blacklist)

	blacklistEmails, err := existingBlacklistSenders(config.Blacklist)
	if err != nil {
		return 0, err
	}
	slog.Info("blacklist senders loaded", "blacklist", config.Blacklist, "count", len(blacklistEmails))

	return ImportEmailsContext(ctx, blacklistEmails, config)
}

func ImportEmails(emails []string, config ImporterConfig) (int, error) {
	if config.Timeout <= 0 {
		return 0, fmt.Errorf("import timeout must be greater than zero")
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	return ImportEmailsContext(ctx, emails, config)
}

func ImportEmailsContext(ctx context.Context, emails []string, config ImporterConfig) (int, error) {
	name := strings.TrimSpace(config.WhoName)
	if name == "" {
		return 0, fmt.Errorf("PMG who name is required")
	}
	excludedEmails, err := readEmailList(config.Exclude)
	if err != nil {
		return 0, err
	}
	emails = excludeEmails(emails, excludedEmails)

	slog.Info("starting PMG who email import",
		"who_name", name,
		"count", len(emails),
		"exclude", config.Exclude,
		"excluded_count", len(excludedEmails),
		"import_timeout", config.Timeout.String(),
	)

	id, err := pmgWhoIDContext(ctx, name)
	if err != nil {
		return 0, err
	}
	slog.Info("PMG who object found", "who_name", name, "id", id)
	objects, err := pmgWhoObjectsContext(ctx, id)
	if err != nil {
		return 0, err
	}
	slog.Info("PMG who objects loaded", "who_name", name, "id", id, "count", len(objects))

	missingEmails := missingPMGWhoEmails(emails, objects)
	slog.Info("missing PMG who emails found", "who_name", name, "id", id, "count", len(missingEmails))
	for _, email := range missingEmails {
		if err := pmgCreateWhoEmailContext(ctx, id, email); err != nil {
			return 0, err
		}
		slog.Info("PMG who email created", "who_name", name, "id", id, "email", email)
	}

	return id, nil
}

func excludeEmails(emails []string, excluded []string) []string {
	var normalizedExcluded []string
	for _, email := range excluded {
		email = strings.ToLower(strings.TrimSpace(email))
		if email != "" && !slices.Contains(normalizedExcluded, email) {
			normalizedExcluded = append(normalizedExcluded, email)
		}
	}

	var included []string
	for _, email := range emails {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			continue
		}
		if slices.Contains(normalizedExcluded, email) || slices.Contains(included, email) {
			continue
		}
		included = append(included, email)
	}

	return included
}

func pmgWhoID(name string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return pmgWhoIDContext(ctx, name)
}

func pmgWhoIDContext(ctx context.Context, name string) (int, error) {
	pmgshCmd, cancel, err := cmd.NewContext(
		ctx,
		"pmgsh",
		[]string{"get", "/config/ruledb/who"},
	)
	if err != nil {
		return 0, fmt.Errorf("create pmgsh command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		if strings.TrimSpace(string(out)) != "" {
			return 0, fmt.Errorf("pmgsh failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return 0, fmt.Errorf("pmgsh failed: %w", err)
	}

	return pmgWhoIDFromOutput(out, name)
}

func pmgWhoIDFromOutput(out []byte, name string) (int, error) {
	who, err := parsePMGWhoOutput(out)
	if err != nil {
		return 0, err
	}

	for _, item := range who {
		if item.Name == name {
			return item.ID, nil
		}
	}

	return 0, fmt.Errorf("PMG who object %q not found", name)
}

func parsePMGWhoOutput(out []byte) ([]pmgWho, error) {
	var who []pmgWho
	if err := decodePMGJSONArray(out, &who); err != nil {
		return nil, fmt.Errorf("parse pmgsh who output: %w", err)
	}

	return who, nil
}

func pmgWhoObjects(id int, timeout time.Duration) ([]pmgWhoObject, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return pmgWhoObjectsContext(ctx, id)
}

func pmgWhoObjectsContext(ctx context.Context, id int) ([]pmgWhoObject, error) {
	pmgshCmd, cancel, err := cmd.NewContext(
		ctx,
		"pmgsh",
		[]string{"get", fmt.Sprintf("/config/ruledb/who/%d/objects", id)},
	)
	if err != nil {
		return nil, fmt.Errorf("create pmgsh objects command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		if strings.TrimSpace(string(out)) != "" {
			return nil, fmt.Errorf("pmgsh objects failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil, fmt.Errorf("pmgsh objects failed: %w", err)
	}
	objects, err := pmgWhoObjectsFromOutput(out)
	if err != nil {
		return nil, err
	}
	slog.Debug("PMG who objects parsed", "id", id, "objects", objects)

	return objects, nil
}

func pmgWhoObjectsFromOutput(out []byte) ([]pmgWhoObject, error) {
	var objects []pmgWhoObject
	if err := decodePMGJSONArray(out, &objects); err != nil {
		return nil, fmt.Errorf("parse pmgsh who objects output: %w", err)
	}

	return objects, nil
}

func missingPMGWhoEmails(blacklistEmails []string, objects []pmgWhoObject) []string {
	var existing []string
	for _, object := range objects {
		email := strings.ToLower(strings.TrimSpace(object.Email))
		if email != "" && !slices.Contains(existing, email) {
			existing = append(existing, email)
		}
	}

	var missing []string
	for _, email := range blacklistEmails {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			continue
		}
		if slices.Contains(existing, email) {
			continue
		}
		missing = append(missing, email)
		existing = append(existing, email)
	}

	return missing
}

func pmgCreateWhoEmail(id int, email string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return pmgCreateWhoEmailContext(ctx, id, email)
}

func pmgCreateWhoEmailContext(ctx context.Context, id int, email string) error {
	pmgshCmd, cancel, err := cmd.NewContext(
		ctx,
		"pmgsh",
		[]string{"create", fmt.Sprintf("/config/ruledb/who/%d/email", id), "--email", email},
	)
	if err != nil {
		return fmt.Errorf("create pmgsh email command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		if strings.TrimSpace(string(out)) != "" {
			return fmt.Errorf("pmgsh create email %q failed: %w: %s", email, err, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("pmgsh create email %q failed: %w", email, err)
	}
	slog.Debug("PMG who email create response received", "id", id, "email", email, "response", strings.TrimSpace(string(out)))

	return nil
}

func decodePMGJSONArray(out []byte, v any) error {
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
