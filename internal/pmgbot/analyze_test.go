package pmgbot

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeSpamMessagesCountsSenderAndSubject(t *testing.T) {
	rows := analyzeSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "b@example.com", Subject: "Same"},
		{EnvelopeSender: "a@example.com", Subject: "Same"},
		{EnvelopeSender: "b@example.com", Subject: "Other"},
		{EnvelopeSender: "b@example.com", Subject: "Same"},
	})

	want := []spamAnalysisRow{
		{EnvelopeSender: "b@example.com", Subject: "Same", Count: 2},
		{EnvelopeSender: "a@example.com", Subject: "Same", Count: 1},
		{EnvelopeSender: "b@example.com", Subject: "Other", Count: 1},
	}
	if len(rows) != len(want) {
		t.Fatalf("got rows %#v, want %#v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Fatalf("got rows %#v, want %#v", rows, want)
		}
	}
}

func TestAnalyzeWritesRows(t *testing.T) {
	originalSpam := quarantineSpamContext
	t.Cleanup(func() { quarantineSpamContext = originalSpam })

	quarantineSpamContext = func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{EnvelopeSender: "sender@example.com", Subject: "Subject"},
			{EnvelopeSender: "sender@example.com", Subject: "Subject"},
		}, nil
	}

	var out bytes.Buffer
	err := Analyze(context.Background(), DaemonConfig{Timeout: time.Minute}, &out)
	if err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(out.String()) != "sender@example.com - Subject - 2" {
		t.Fatalf("got output %q", out.String())
	}
}

func TestAnalyzeValidatesTimeout(t *testing.T) {
	err := Analyze(context.Background(), DaemonConfig{Timeout: 0}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}
