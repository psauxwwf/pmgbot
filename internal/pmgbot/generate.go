package pmgbot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultGeneratedRuleMinCount = 2

type RuleGenerationConfig struct {
	Action   string
	MinCount int
}

type ruleGenerationCandidate struct {
	Subject      string
	Count        int
	FieldSenders []ruleGenerationFieldSenders
}

type ruleGenerationFieldSenders struct {
	Field   string
	Senders []string
}

type generatedRulesFile struct {
	Rules Rules `yaml:"rules"`
}

func GenerateRules(ctx context.Context, config DaemonConfig, ruleConfig RuleGenerationConfig, output io.Writer) error {
	return generateRules(ctx, config, ruleConfig, output, pmgQuarantineSpamContext)
}

func GenerateRulesFromSpamJSON(path string, config RuleGenerationConfig, output io.Writer) error {
	messages, err := readSpamMessagesJSON(path)
	if err != nil {
		return err
	}

	return writeGeneratedRules(messages, config, output)
}

func generateRules(
	ctx context.Context,
	config DaemonConfig,
	ruleConfig RuleGenerationConfig,
	output io.Writer,
	quarantineSpam quarantineSpamFunc,
) error {
	if config.Timeout <= 0 {
		return fmt.Errorf("daemon timeout must be greater than zero")
	}

	cycleCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	messages, err := quarantineSpam(cycleCtx)
	cancel()
	if err != nil {
		return err
	}

	return writeGeneratedRules(messages, ruleConfig, output)
}

func writeGeneratedRules(messages []quarantineSpamMessage, config RuleGenerationConfig, output io.Writer) error {
	rules, err := GenerateRulesFromSpamMessages(messages, config)
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(generatedRulesFile{Rules: rules})
	if err != nil {
		return fmt.Errorf("marshal generated rules: %w", err)
	}
	if _, err := output.Write(data); err != nil {
		return fmt.Errorf("write generated rules: %w", err)
	}

	return nil
}

func GenerateRulesFromSpamMessages(messages []quarantineSpamMessage, config RuleGenerationConfig) (Rules, error) {
	action := quarantineAction(strings.TrimSpace(config.Action))
	if action == "" {
		action = quarantineActionDelete
	}
	if !slices.Contains(quarantineActions, action) {
		return nil, fmt.Errorf("invalid action %q", action)
	}

	minCount := config.MinCount
	if minCount <= 0 {
		minCount = defaultGeneratedRuleMinCount
	}
	candidates := repeatedSubjectCandidates(messages, minCount)

	rules := make(Rules, 0, len(candidates))
	for _, candidate := range candidates {
		when := make(RuleGroups, 0, len(candidate.FieldSenders))
		for _, fieldSenders := range candidate.FieldSenders {
			when = append(when, FieldPatterns{
				fieldSenders.Field: exactRegexps(fieldSenders.Senders),
				"subject":          {exactRegexp(candidate.Subject)},
			})
		}

		rules = append(rules, Rule{
			Name:   generatedRuleName(action, candidate),
			Action: action,
			When:   when,
		})
	}

	return rules, nil
}

func readSpamMessagesJSON(path string) ([]quarantineSpamMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spam json %s: %w", path, err)
	}

	trimmed := strings.TrimSpace(string(data))
	start := strings.Index(trimmed, "[")
	if start < 0 {
		return nil, fmt.Errorf("read spam json %s: no JSON array found", path)
	}

	var messages []quarantineSpamMessage
	if err := json.NewDecoder(strings.NewReader(trimmed[start:])).Decode(&messages); err != nil {
		return nil, fmt.Errorf("parse spam json %s: %w", path, err)
	}

	return messages, nil
}

func repeatedSubjectCandidates(messages []quarantineSpamMessage, minCount int) []ruleGenerationCandidate {
	type subjectGroup struct {
		Count  int
		Fields map[string][]string
	}

	groups := make(map[string]*subjectGroup)
	for _, message := range messages {
		subject := strings.TrimSpace(message.Subject)
		if subject == "" {
			continue
		}

		group, ok := groups[subject]
		if !ok {
			group = &subjectGroup{Fields: make(map[string][]string)}
			groups[subject] = group
		}
		group.Count++

		field, sender := messageIdentityField(message)
		if sender == "" {
			continue
		}

		if !slices.Contains(group.Fields[field], sender) {
			group.Fields[field] = append(group.Fields[field], sender)
		}
	}

	candidates := make([]ruleGenerationCandidate, 0, len(groups))
	for subject, group := range groups {
		if group.Count < minCount || len(group.Fields) == 0 {
			continue
		}

		fields := make([]string, 0, len(group.Fields))
		for field := range group.Fields {
			fields = append(fields, field)
		}
		sort.Strings(fields)

		fieldSenders := make([]ruleGenerationFieldSenders, 0, len(fields))
		for _, field := range fields {
			senders := slices.Clone(group.Fields[field])
			sort.Strings(senders)
			fieldSenders = append(fieldSenders, ruleGenerationFieldSenders{
				Field:   field,
				Senders: senders,
			})
		}

		candidates = append(candidates, ruleGenerationCandidate{
			Subject:      subject,
			Count:        group.Count,
			FieldSenders: fieldSenders,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Count != candidates[j].Count {
			return candidates[i].Count > candidates[j].Count
		}
		if candidates[i].Subject != candidates[j].Subject {
			return candidates[i].Subject < candidates[j].Subject
		}

		return len(candidates[i].FieldSenders) < len(candidates[j].FieldSenders)
	})

	return candidates
}

func messageIdentityField(message quarantineSpamMessage) (string, string) {
	if sender := strings.TrimSpace(message.EnvelopeSender); sender != "" {
		return "envelope_sender", sender
	}

	return "from", strings.TrimSpace(message.From)
}

func generatedRuleName(action quarantineAction, candidate ruleGenerationCandidate) string {
	name := fmt.Sprintf("Generated %s repeated spam (%d): %s", action, candidate.Count, candidate.Subject)
	return truncateRuleName(collapseWhitespace(name), 120)
}

func exactRegexp(value string) string {
	return "^" + regexp.QuoteMeta(value) + "$"
}

func exactRegexps(values []string) []string {
	patterns := make([]string, 0, len(values))
	for _, value := range values {
		patterns = append(patterns, exactRegexp(value))
	}

	return patterns
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func truncateRuleName(value string, maxLength int) string {
	runes := []rune(value)
	if len(runes) <= maxLength {
		return value
	}

	return string(runes[:maxLength])
}
