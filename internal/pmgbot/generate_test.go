package pmgbot

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGenerateRulesFromSpamMessages(t *testing.T) {
	rules, err := GenerateRulesFromSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "sender@example.com", Subject: "Repeated"},
		{EnvelopeSender: "sender@example.com", Subject: "Repeated"},
		{EnvelopeSender: "sender@example.com", Subject: "Repeated"},
		{EnvelopeSender: "other@example.com", Subject: "Repeated"},
		{From: "Mail Delivery <mailer@example.com>", Subject: "Bounce"},
		{From: "Mail Delivery <mailer@example.com>", Subject: "Bounce"},
		{EnvelopeSender: "single@example.com", Subject: "Single"},
	}, RuleGenerationConfig{MinCount: 2})
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Action != quarantineActionDelete || !strings.Contains(rules[0].Name, "(4)") {
		t.Fatalf("got first rule %#v", rules[0])
	}
	if got, want := rules[0].When[0]["envelope_sender"], []string{`^other@example\.com$`, `^sender@example\.com$`}; !slices.Equal(got, want) {
		t.Fatalf("got sender patterns %#v, want %#v", got, want)
	}
	if got := rules[0].When[0]["subject"][0]; got != `^Repeated$` {
		t.Fatalf("got subject pattern %q", got)
	}
	if got := rules[1].When[0]["from"][0]; got != `^Mail Delivery <mailer@example\.com>$` {
		t.Fatalf("got from pattern %q", got)
	}
	if _, ok := rules[1].When[0]["envelope_sender"]; ok {
		t.Fatalf("got unexpected envelope_sender in fallback rule %#v", rules[1])
	}
}

func TestGenerateRulesFromSpamMessagesHonorsAction(t *testing.T) {
	rules, err := GenerateRulesFromSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "a@example.com", Subject: "A"},
		{EnvelopeSender: "a@example.com", Subject: "A"},
		{EnvelopeSender: "b@example.com", Subject: "B"},
		{EnvelopeSender: "b@example.com", Subject: "B"},
	}, RuleGenerationConfig{Action: "deliver", MinCount: 2})
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 2 {
		t.Fatalf("got %d rules, want all 2", len(rules))
	}
	if rules[0].Action != quarantineActionDeliver {
		t.Fatalf("got action %q, want deliver", rules[0].Action)
	}
}

func TestGenerateRulesFromSpamMessagesSplitsIdentityFields(t *testing.T) {
	rules, err := GenerateRulesFromSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "a@example.com", Subject: "Mixed"},
		{From: "Fallback <fallback@example.com>", Subject: "Mixed"},
	}, RuleGenerationConfig{MinCount: 2})
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if len(rules[0].When) != 2 {
		t.Fatalf("got %d when groups, want 2", len(rules[0].When))
	}
	if _, ok := rules[0].When[0]["envelope_sender"]; !ok {
		t.Fatalf("got first group %#v, want envelope_sender", rules[0].When[0])
	}
	if _, ok := rules[0].When[1]["from"]; !ok {
		t.Fatalf("got second group %#v, want from", rules[0].When[1])
	}
}

func TestGenerateRulesFromSpamMessagesValidatesAction(t *testing.T) {
	_, err := GenerateRulesFromSpamMessages(nil, RuleGenerationConfig{Action: "archive"})
	if err == nil {
		t.Fatal("expected invalid action error")
	}
}

func TestGenerateRulesFromSpamJSONWritesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spam.json")
	data := `200 OK
[{"envelope_sender":"sender@example.com","subject":"Subject"},{"envelope_sender":"sender@example.com","subject":"Subject"}]
done`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := GenerateRulesFromSpamJSON(path, RuleGenerationConfig{MinCount: 2}, &out); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"rules:",
		"name: 'Generated delete repeated spam (2): Subject'",
		"action: delete",
		"envelope_sender:",
		"- ^sender@example\\.com$",
		"subject:",
		"- ^Subject$",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestGenerateRulesLoadsSpamThroughPMG(t *testing.T) {
	var out bytes.Buffer
	err := generateRules(
		context.Background(),
		DaemonConfig{Timeout: time.Minute},
		RuleGenerationConfig{MinCount: 2},
		&out,
		func(context.Context) ([]quarantineSpamMessage, error) {
			return []quarantineSpamMessage{
				{EnvelopeSender: "sender@example.com", Subject: "Subject"},
				{EnvelopeSender: "sender@example.com", Subject: "Subject"},
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{"rules:", "envelope_sender:", "^sender@example\\.com$"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestGenerateRulesValidatesTimeout(t *testing.T) {
	err := generateRules(
		context.Background(),
		DaemonConfig{},
		RuleGenerationConfig{},
		io.Discard,
		func(context.Context) ([]quarantineSpamMessage, error) {
			t.Fatal("quarantine spam must not be called with invalid timeout")
			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}
