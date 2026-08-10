package pmgbot

import (
	"context"
	"regexp"
	"slices"
	"testing"
	"time"
)

func TestDaemonValidatesEvery(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Every:   0,
		Timeout: time.Minute,
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDaemonValidatesTimeout(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Every:   time.Minute,
		Timeout: 0,
	})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}

func TestDaemonValidatesRulePatterns(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Every:   time.Minute,
		Timeout: time.Minute,
		Rules: Rules{
			{
				Name:   "Bad regexp",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"subject": {"["}}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected pattern validation error")
	}
}

func TestDaemonValidatesRuleActions(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Every:   time.Minute,
		Timeout: time.Minute,
		Rules: Rules{
			{
				Name:   "Bad action",
				Action: "archive",
				When:   RuleGroups{{"subject": {`.*`}}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected action validation error")
	}
}

func TestRunOnceDoesNotValidateEvery(t *testing.T) {
	err := runDaemonOnce(context.Background(), DaemonConfig{
		Every:   0,
		Timeout: time.Minute,
	}, nil, func(context.Context) ([]quarantineSpamMessage, error) {
		return nil, nil
	}, func(context.Context, string, quarantineAction) error {
		return nil
	})
	if err != nil {
		t.Fatalf("expected one-shot run without daemon every, got %v", err)
	}
}

func TestRunOnceValidatesTimeout(t *testing.T) {
	err := RunOnce(context.Background(), DaemonConfig{Timeout: 0})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}

func TestCheckDoesNotApplyActions(t *testing.T) {
	rules, err := compileRules(Rules{{
		Name:   "Delete spam",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {`Lottery`}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	err = runDaemonCheck(context.Background(), DaemonConfig{Timeout: time.Minute}, rules, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "delete-id", Subject: "Lottery", EnvelopeSender: "bad@example.com"},
			{ID: "skip-id", Subject: "Normal"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunDaemonOnceAppliesActionsAndContinuesOnError(t *testing.T) {
	quarantineSpam := func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "deliver-id", Subject: "Important", EnvelopeSender: "bad@example.com"},
			{ID: "delete-id", Subject: "Lottery", EnvelopeSender: "bad@example.com"},
			{ID: "skip-id", Subject: "Normal"},
			{ID: "fail-id", Subject: "Casino"},
		}, nil
	}

	var actions []string
	applyQuarantineAction := func(_ context.Context, id string, action quarantineAction) error {
		actions = append(actions, id+":"+string(action))
		if id == "fail-id" {
			return context.Canceled
		}
		return nil
	}

	rules := []compiledRule{
		{
			Name:   "Deliver important",
			Action: quarantineActionDeliver,
			When: compiledRuleGroups{{
				"subject": {regexp.MustCompile(`Important`)},
			}},
		},
		{
			Name:   "Delete spam",
			Action: quarantineActionDelete,
			When: compiledRuleGroups{
				{"subject": {regexp.MustCompile(`Lottery|Casino`)}},
				{"envelope_sender": {regexp.MustCompile(`bad@example\.com`)}},
			},
		},
	}
	err := runDaemonOnce(context.Background(), DaemonConfig{Timeout: time.Minute}, rules, quarantineSpam, applyQuarantineAction)
	if err == nil {
		t.Fatal("expected action error")
	}

	expected := []string{"deliver-id:deliver", "delete-id:delete", "fail-id:delete"}
	if !slices.Equal(actions, expected) {
		t.Fatalf("got actions %#v, want %#v", actions, expected)
	}
}
