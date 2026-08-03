package pmgbot

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"pmgbot/pkg/cmd"
)

type quarantineSpamMessage struct {
	Bytes          int64  `json:"bytes"`
	EnvelopeSender string `json:"envelope_sender"`
	From           string `json:"from"`
	ID             string `json:"id"`
	Receiver       string `json:"receiver"`
	SpamLevel      int64  `json:"spamlevel"`
	Subject        string `json:"subject"`
	Time           int64  `json:"time"`
}

type compiledFieldPatterns map[string][]*regexp.Regexp
type compiledRuleGroups []compiledFieldPatterns

type compiledRule struct {
	Name   string
	Action quarantineAction
	When   compiledRuleGroups
}

type quarantineAction string

const (
	quarantineActionDeliver quarantineAction = "deliver"
	quarantineActionDelete  quarantineAction = "delete"
)

var quarantineActions = []quarantineAction{
	quarantineActionDeliver,
	quarantineActionDelete,
}

func pmgQuarantineSpamContext(ctx context.Context) ([]quarantineSpamMessage, error) {
	pmgshCmd, cancel, err := cmd.NewContext(ctx, "pmgsh", []string{"get", "/quarantine/spam"})
	if err != nil {
		return nil, fmt.Errorf("create pmgsh quarantine spam command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		if strings.TrimSpace(string(out)) != "" {
			return nil, fmt.Errorf("pmgsh quarantine spam failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil, fmt.Errorf("pmgsh quarantine spam failed: %w", err)
	}

	return pmgQuarantineSpamFromOutput(out)
}

func pmgQuarantineSpamFromOutput(out []byte) ([]quarantineSpamMessage, error) {
	var messages []quarantineSpamMessage
	if err := decodePMGJSONArray(out, &messages); err != nil {
		return nil, fmt.Errorf("parse pmgsh quarantine spam output: %w", err)
	}

	return messages, nil
}

func compileFieldPatterns(action string, patterns FieldPatterns) (compiledFieldPatterns, error) {
	compiled := make(compiledFieldPatterns)
	for field, fieldPatterns := range patterns {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if !hasFieldPatterns(fieldPatterns) {
			continue
		}
		if !quarantineMessageFieldExists(field) {
			return nil, fmt.Errorf("unknown %s field %q", action, field)
		}

		var seen []string
		for _, pattern := range fieldPatterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" || slices.Contains(seen, pattern) {
				continue
			}

			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("compile %s pattern for field %q %q: %w", action, field, pattern, err)
			}

			seen = append(seen, pattern)
			compiled[field] = append(compiled[field], re)
		}
	}

	return compiled, nil
}

func compileRuleGroups(action string, groups RuleGroups) (compiledRuleGroups, error) {
	compiled := make(compiledRuleGroups, 0, len(groups))
	for _, group := range groups {
		compiledGroup, err := compileFieldPatterns(action, group)
		if err != nil {
			return nil, err
		}
		if len(compiledGroup) == 0 {
			continue
		}

		compiled = append(compiled, compiledGroup)
	}

	return compiled, nil
}

func compileRules(rules Rules) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			name = fmt.Sprintf("rule %d", i+1)
		}

		action := quarantineAction(strings.TrimSpace(string(rule.Action)))
		if !slices.Contains(quarantineActions, action) {
			return nil, fmt.Errorf("%s has invalid action %q", name, rule.Action)
		}

		when, err := compileRuleGroups(name, rule.When)
		if err != nil {
			return nil, err
		}
		if len(when) == 0 {
			return nil, fmt.Errorf("%s must have at least one condition group", name)
		}

		compiled = append(compiled, compiledRule{
			Name:   name,
			Action: action,
			When:   when,
		})
	}

	return compiled, nil
}

func hasFieldPatterns(patterns []string) bool {
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) != "" {
			return true
		}
	}

	return false
}

func matchRuleGroups(message quarantineSpamMessage, groups compiledRuleGroups) bool {
	for _, group := range groups {
		if matchFieldPatternGroup(message, group) {
			return true
		}
	}

	return false
}

func matchFieldPatternGroup(message quarantineSpamMessage, patterns compiledFieldPatterns) bool {
	if len(patterns) == 0 {
		return false
	}

	for field, fieldPatterns := range patterns {
		text, ok := quarantineMessageFieldString(message, field)
		if !ok || text == "" {
			return false
		}

		var matched bool
		for _, pattern := range fieldPatterns {
			if pattern.MatchString(text) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func decideQuarantineAction(
	message quarantineSpamMessage,
	rules []compiledRule,
) (quarantineAction, string, bool) {
	for _, rule := range rules {
		if matchRuleGroups(message, rule.When) {
			return rule.Action, rule.Name, true
		}
	}

	return "", "", false
}

func quarantineSpamID(message quarantineSpamMessage) (string, error) {
	id := strings.TrimSpace(message.ID)
	if id == "" {
		return "", fmt.Errorf("quarantine spam message id is empty")
	}

	return id, nil
}

func quarantineMessageFieldExists(field string) bool {
	_, ok := quarantineMessageFieldString(quarantineSpamMessage{}, field)
	return ok
}

func quarantineMessageFieldString(message quarantineSpamMessage, field string) (string, bool) {
	switch field {
	case "envelope_sender":
		return message.EnvelopeSender, true
	case "from":
		return message.From, true
	case "receiver":
		return message.Receiver, true
	case "subject":
		return message.Subject, true
	default:
		return "", false
	}
}

func pmgApplyQuarantineActionContext(ctx context.Context, id string, action quarantineAction) error {
	pmgshCmd, cancel, err := cmd.NewContext(
		ctx,
		"pmgsh",
		[]string{"create", "/quarantine/content", "--id", id, "--action", string(action)},
	)
	if err != nil {
		return fmt.Errorf("create pmgsh quarantine action command: %w", err)
	}
	defer cancel()

	out, err := pmgshCmd.Run()
	if err != nil {
		if strings.TrimSpace(string(out)) != "" {
			return fmt.Errorf("pmgsh quarantine %s %q failed: %w: %s", action, id, err, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("pmgsh quarantine %s %q failed: %w", action, id, err)
	}
	slog.Debug("PMG quarantine action response received", "id", id, "action", action, "response", strings.TrimSpace(string(out)))

	return nil
}
