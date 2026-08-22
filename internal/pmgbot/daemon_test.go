package pmgbot

import (
	"context"
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

func TestRunDaemonOnceHonorsCountCondition(t *testing.T) {
	rules, err := compileRules(Rules{{
		Name:   "Delete repeated subjects",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {sameValuePattern}, "count": {"3"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var actions []string
	err = runDaemonOnce(context.Background(), DaemonConfig{Timeout: time.Minute}, rules, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "1", Subject: "TEST"},
			{ID: "2", Subject: "TEST"},
			{ID: "3", Subject: "OTHER"},
		}, nil
	}, func(_ context.Context, id string, action quarantineAction) error {
		actions = append(actions, id+":"+string(action))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("got actions %#v, want none below count", actions)
	}

	err = runDaemonOnce(context.Background(), DaemonConfig{Timeout: time.Minute}, rules, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "1", Subject: "TEST"},
			{ID: "2", Subject: "TEST"},
			{ID: "3", Subject: "TEST"},
		}, nil
	}, func(_ context.Context, id string, action quarantineAction) error {
		actions = append(actions, id+":"+string(action))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"1:delete", "2:delete", "3:delete"}
	if !slices.Equal(actions, expected) {
		t.Fatalf("got actions %#v, want %#v", actions, expected)
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

	rules, err := compileRules(Rules{
		{
			Name:   "Deliver important",
			Action: quarantineActionDeliver,
			When:   RuleGroups{{"subject": {`Important`}}},
		},
		{
			Name:   "Delete spam",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{"subject": {`Lottery|Casino`}},
				{"envelope_sender": {`bad@example\.com`}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = runDaemonOnce(context.Background(), DaemonConfig{Timeout: time.Minute}, rules, quarantineSpam, applyQuarantineAction)
	if err == nil {
		t.Fatal("expected action error")
	}

	expected := []string{"deliver-id:deliver", "delete-id:delete", "fail-id:delete"}
	if !slices.Equal(actions, expected) {
		t.Fatalf("got actions %#v, want %#v", actions, expected)
	}
}
