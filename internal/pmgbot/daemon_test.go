package pmgbot

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDaemonValidatesCron(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Timeout: time.Minute,
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDaemonValidatesTimeout(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Cron:    "0 8 * * *",
		Timeout: 0,
	})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}

func TestDaemonValidatesRulePatterns(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Cron:    "0 8 * * *",
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
		Cron:    "0 8 * * *",
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

func TestRunOnceDoesNotValidateCron(t *testing.T) {
	err := runDaemonOnce(context.Background(), DaemonConfig{
		Timeout: time.Minute,
	}, nil, func(context.Context) ([]quarantineSpamMessage, error) {
		return nil, nil
	}, func(context.Context, string, quarantineAction) error {
		return nil
	})
	if err != nil {
		t.Fatalf("expected one-shot run without daemon cron, got %v", err)
	}
}

func TestCronIncludesSeconds(t *testing.T) {
	if !cronIncludesSeconds("0 */15 * * * *") {
		t.Fatal("expected six-field cron to include seconds")
	}
	if cronIncludesSeconds("*/15 * * * *") {
		t.Fatal("expected five-field cron not to include seconds")
	}
	if !cronIncludesSeconds("CRON_TZ=Europe/Moscow 0 0 8 * * *") {
		t.Fatal("expected six-field cron with timezone to include seconds")
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

func TestWriteDaemonCycleReport(t *testing.T) {
	report := daemonCycleReport{
		DryRun:    true,
		Total:     3,
		Delivered: 1,
		Deleted:   1,
		Skipped:   1,
		Actions: []daemonCycleActionRow{
			{
				ID:       "delete-id",
				Action:   quarantineActionDelete,
				RuleName: "Delete spam",
				Message: quarantineSpamMessage{
					EnvelopeSender: "bad@example.com",
					From:           "Bad <bad@example.com>",
					Receiver:       "user@example.com",
					Subject:        "Lottery",
				},
			},
			{
				ID:       "deliver-id",
				Action:   quarantineActionDeliver,
				RuleName: "Deliver trusted",
				Message: quarantineSpamMessage{
					EnvelopeSender: "trusted@example.com",
					From:           "Trusted <trusted@example.com>",
					Receiver:       "user@example.com",
					Subject:        "Important",
				},
			},
		},
	}

	var out bytes.Buffer
	if err := writeDaemonCycleReport(&out, report); err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"Lottery | delete-id",
		"bad@example.com | Bad <bad@example.com> | user@example.com | [delete:Delete spam]",
		"---",
		"Important | deliver-id",
		"trusted@example.com | Trusted <trusted@example.com> | user@example.com | [deliver:Deliver trusted]",
		"---",
		"summary | total: 3 | deliver: 1 | delete: 1 | skip: 1 | errors: 0",
	}, "\n")
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("got output %q", out.String())
	}
}

func TestRunDaemonOnceOutputStreamsActions(t *testing.T) {
	rules, err := compileRules(Rules{{
		Name:   "Delete all",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {`Spam`}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	_, err = runDaemonOnceReportOutput(context.Background(), DaemonConfig{Timeout: time.Minute}, rules, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "1", Subject: "Spam", EnvelopeSender: "first@example.com"},
			{ID: "2", Subject: "Spam", EnvelopeSender: "second@example.com"},
		}, nil
	}, func(_ context.Context, id string, _ quarantineAction) error {
		if id == "2" && !strings.Contains(out.String(), "Spam | 1") {
			t.Fatalf("first action was not printed before second action, got %q", out.String())
		}
		return nil
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "summary | total: 2 | deliver: 0 | delete: 2 | skip: 0 | errors: 0") {
		t.Fatalf("got output %q", out.String())
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
