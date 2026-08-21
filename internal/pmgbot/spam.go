package pmgbot

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"pmgbot/pkg/lang"
	"pmgbot/pkg/pmg"
)

type quarantineSpamMessage = pmg.SpamMessage

type compiledPattern struct {
	Regexp   *regexp.Regexp
	Inverted bool
}

type compiledFieldPatterns map[string][]compiledPattern

type countOperator string

type countCondition struct {
	Operator countOperator
	Value    int
}

type compiledRuleGroup struct {
	Patterns compiledFieldPatterns
	Count    countCondition
}

type compiledRuleGroups []compiledRuleGroup

type compiledRule struct {
	Name   string
	Action quarantineAction
	When   compiledRuleGroups
}

type quarantineAction string

const (
	quarantineActionDeliver quarantineAction = "deliver"
	quarantineActionDelete  quarantineAction = "delete"
	invertedPatternPrefix   string           = "[!]"
	ruleCountField          string           = "count"
	countEqualOrGreater     countOperator    = ">="
	countGreater            countOperator    = ">"
	countEqualOrLess        countOperator    = "<="
	countLess               countOperator    = "<"
)

var quarantineActions = []quarantineAction{
	quarantineActionDeliver,
	quarantineActionDelete,
}

func pmgQuarantineSpamContext(ctx context.Context) ([]quarantineSpamMessage, error) {
	return pmg.QuarantineSpam(ctx)
}

func compileFieldPatterns(action string, patterns FieldPatterns) (compiledFieldPatterns, error) {
	compiled := make(compiledFieldPatterns)
	for field, fieldPatterns := range patterns {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if field == ruleCountField {
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

			patternText, inverted := patternRegexp(pattern)
			if patternText == "" {
				continue
			}

			re, err := regexp.Compile(patternText)
			if err != nil {
				return nil, fmt.Errorf("compile %s pattern for field %q %q: %w", action, field, pattern, err)
			}

			seen = append(seen, pattern)
			compiled[field] = append(compiled[field], compiledPattern{Regexp: re, Inverted: inverted})
		}
	}

	return compiled, nil
}

func patternRegexp(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, invertedPatternPrefix) {
		return pattern, false
	}

	return strings.TrimSpace(strings.TrimPrefix(pattern, invertedPatternPrefix)), true
}

func compileRuleGroups(action string, groups RuleGroups) (compiledRuleGroups, error) {
	compiled := make(compiledRuleGroups, 0, len(groups))
	for _, group := range groups {
		count, err := ruleGroupCount(action, group)
		if err != nil {
			return nil, err
		}

		compiledGroup, err := compileFieldPatterns(action, group)
		if err != nil {
			return nil, err
		}
		if len(compiledGroup) == 0 {
			continue
		}

		compiled = append(compiled, compiledRuleGroup{Patterns: compiledGroup, Count: count})
	}

	return compiled, nil
}

func ruleGroupCount(action string, group FieldPatterns) (countCondition, error) {
	patterns, ok := group[ruleCountField]
	if !ok || !hasFieldPatterns(patterns) {
		return countCondition{}, nil
	}
	if len(patterns) != 1 {
		return countCondition{}, fmt.Errorf("%s count must be a single integer with optional comparison operator", action)
	}

	countText := strings.TrimSpace(patterns[0])
	operator, countText := parseCountOperator(countText)
	count, err := strconv.Atoi(countText)
	if err != nil {
		return countCondition{}, fmt.Errorf("%s count must be a single integer with optional comparison operator: %q", action, patterns[0])
	}
	if count < 1 {
		return countCondition{}, fmt.Errorf("%s count must be at least 1", action)
	}

	return countCondition{Operator: operator, Value: count}, nil
}

func parseCountOperator(countText string) (countOperator, string) {
	for _, operator := range []countOperator{countEqualOrGreater, countEqualOrLess, countGreater, countLess} {
		operatorText := string(operator)
		if strings.HasPrefix(countText, operatorText) {
			return operator, strings.TrimSpace(strings.TrimPrefix(countText, operatorText))
		}
	}

	return countEqualOrGreater, countText
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

func matchRuleGroups(message quarantineSpamMessage, groups compiledRuleGroups, messages []quarantineSpamMessage) bool {
	for _, group := range groups {
		if matchRuleGroup(message, group, messages) {
			return true
		}
	}

	return false
}

func matchRuleGroup(message quarantineSpamMessage, group compiledRuleGroup, messages []quarantineSpamMessage) bool {
	if !matchFieldPatternGroup(message, group.Patterns) {
		return false
	}
	if !group.Count.Enabled() {
		return true
	}

	return group.Count.Matches(countMatchingMessages(messages, group.Patterns))
}

func (condition countCondition) Enabled() bool {
	return condition.Value > 0
}

func (condition countCondition) Matches(count int) bool {
	switch condition.Operator {
	case countGreater:
		return count > condition.Value
	case countLess:
		return count < condition.Value
	case countEqualOrLess:
		return count <= condition.Value
	default:
		return count >= condition.Value
	}
}

func countMatchingMessages(messages []quarantineSpamMessage, patterns compiledFieldPatterns) int {
	var count int
	for _, message := range messages {
		if matchFieldPatternGroup(message, patterns) {
			count++
		}
	}

	return count
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
			if pattern.Matches(text) {
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

func (pattern compiledPattern) Matches(text string) bool {
	matched := pattern.Regexp.MatchString(text)
	if pattern.Inverted {
		return !matched
	}

	return matched
}

func decideQuarantineAction(
	message quarantineSpamMessage,
	rules []compiledRule,
) (quarantineAction, string, bool) {
	return decideQuarantineActionForMessages(message, []quarantineSpamMessage{message}, rules)
}

func decideQuarantineActionForMessages(
	message quarantineSpamMessage,
	messages []quarantineSpamMessage,
	rules []compiledRule,
) (quarantineAction, string, bool) {
	for _, rule := range rules {
		if matchRuleGroups(message, rule.When, messages) {
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
	case "subject_script":
		return lang.SubjectScript(message.Subject), true
	case "subject_language":
		return lang.SubjectLanguage(message.Subject), true
	default:
		return "", false
	}
}

func pmgApplyQuarantineActionContext(ctx context.Context, id string, action quarantineAction) error {
	out, err := pmg.ApplyQuarantineAction(ctx, id, string(action))
	if err != nil {
		return err
	}
	slog.Debug("PMG quarantine action response received", "id", id, "action", action, "response", strings.TrimSpace(string(out)))

	return nil
}
