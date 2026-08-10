package pmgbot

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeSpamMessagesGroupsBySubject(t *testing.T) {
	rows := analyzeSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "b@example.com", Subject: "Same"},
		{EnvelopeSender: "a@example.com", Subject: "Same"},
		{EnvelopeSender: "b@example.com", Subject: "Other"},
		{EnvelopeSender: "b@example.com", Subject: "Same"},
		{EnvelopeSender: "a@example.com", Subject: "Other"},
		{EnvelopeSender: "a@example.com", Subject: "Other"},
		{EnvelopeSender: "c@example.com", Subject: "Same"},
	})

	want := []spamAnalysisRow{
		{
			Subject: "Same",
			Count:   4,
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "b@example.com", Count: 2},
				{EnvelopeSender: "a@example.com", Count: 1},
				{EnvelopeSender: "c@example.com", Count: 1},
			},
		},
		{
			Subject: "Other",
			Count:   3,
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "a@example.com", Count: 2},
				{EnvelopeSender: "b@example.com", Count: 1},
			},
		},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got rows %#v, want %#v", rows, want)
	}
}

func TestAnalyzeWritesRows(t *testing.T) {
	var out bytes.Buffer
	err := analyze(context.Background(), DaemonConfig{Timeout: time.Minute}, &out, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{EnvelopeSender: "sender@example.com", Subject: "Subject"},
			{EnvelopeSender: "sender@example.com", Subject: "Subject"},
			{EnvelopeSender: "other@example.com", Subject: "Subject"},
			{EnvelopeSender: "other@example.com", Subject: "Other"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"Subject - 3",
		"sender@example.com - 2",
		"other@example.com - 1",
		"---",
		"Other - 1",
		"other@example.com - 1",
	}, "\n")
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("got output %q", out.String())
	}
}

func TestAnalyzeValidatesTimeout(t *testing.T) {
	err := Analyze(context.Background(), DaemonConfig{Timeout: 0}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}
