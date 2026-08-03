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

func TestDaemonValidatesDeliverPatterns(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Every:   time.Minute,
		Timeout: time.Minute,
		Deliver: FieldPatterns{
			"subject": {"["},
		},
	})
	if err == nil {
		t.Fatal("expected deliver pattern validation error")
	}
}

func TestDaemonValidatesDeletePatterns(t *testing.T) {
	err := Daemon(context.Background(), DaemonConfig{
		Every:   time.Minute,
		Timeout: time.Minute,
		Delete: FieldPatterns{
			"subject": {"["},
		},
	})
	if err == nil {
		t.Fatal("expected delete pattern validation error")
	}
}

func TestRunOnceDoesNotValidateEvery(t *testing.T) {
	originalSpam := quarantineSpamContext
	t.Cleanup(func() { quarantineSpamContext = originalSpam })

	quarantineSpamContext = func(context.Context) ([]quarantineSpamMessage, error) {
		return nil, nil
	}

	err := RunOnce(context.Background(), DaemonConfig{
		Every:   0,
		Timeout: time.Minute,
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

func TestRunDaemonOnceAppliesActionsAndContinuesOnError(t *testing.T) {
	originalSpam := quarantineSpamContext
	originalAction := applyQuarantineActionContext
	t.Cleanup(func() {
		quarantineSpamContext = originalSpam
		applyQuarantineActionContext = originalAction
	})

	quarantineSpamContext = func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "deliver-id", Subject: "Important", EnvelopeSender: "bad@example.com"},
			{ID: "delete-id", Subject: "Lottery", EnvelopeSender: "bad@example.com"},
			{ID: "skip-id", Subject: "Normal"},
			{ID: "fail-id", Subject: "Casino"},
		}, nil
	}

	var actions []string
	applyQuarantineActionContext = func(_ context.Context, id string, action quarantineAction) error {
		actions = append(actions, id+":"+string(action))
		if id == "fail-id" {
			return context.Canceled
		}
		return nil
	}

	deliver := compiledFieldPatterns{
		"subject": {regexp.MustCompile(`Important`)},
	}
	delete := compiledFieldPatterns{
		"subject":         {regexp.MustCompile(`Lottery|Casino`)},
		"envelope_sender": {regexp.MustCompile(`bad@example\.com`)},
	}
	err := runDaemonOnce(context.Background(), DaemonConfig{Timeout: time.Minute}, deliver, delete)
	if err == nil {
		t.Fatal("expected action error")
	}

	expected := []string{"deliver-id:deliver", "delete-id:delete", "fail-id:delete"}
	if !slices.Equal(actions, expected) {
		t.Fatalf("got actions %#v, want %#v", actions, expected)
	}
}
