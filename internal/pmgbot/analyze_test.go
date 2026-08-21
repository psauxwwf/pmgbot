package pmgbot

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeSpamMessagesGroupsBySubject(t *testing.T) {
	rows := analyzeSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Subject: "Same"},
		{EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", Subject: "Same"},
		{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Subject: "Other"},
		{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Subject: "Same"},
		{EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", Subject: "Other"},
		{EnvelopeSender: "a@example.com", From: "Other Alpha <a@example.com>", Subject: "Other"},
		{EnvelopeSender: "c@example.com", From: "Charlie <c@example.com>", Subject: "Same"},
	}, 1, nil)

	want := []spamAnalysisRow{
		{
			Subject:  "Same",
			Count:    4,
			Script:   "latin",
			Language: "unknown",
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Count: 2, Action: "skip"},
				{EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", Count: 1, Action: "skip"},
				{EnvelopeSender: "c@example.com", From: "Charlie <c@example.com>", Count: 1, Action: "skip"},
			},
		},
		{
			Subject:  "Other",
			Count:    3,
			Script:   "latin",
			Language: "en",
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", Count: 1, Action: "skip"},
				{EnvelopeSender: "a@example.com", From: "Other Alpha <a@example.com>", Count: 1, Action: "skip"},
				{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Count: 1, Action: "skip"},
			},
		},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got rows %#v, want %#v", rows, want)
	}
}

func TestAnalyzeSpamMessagesFiltersBySubjectMinCount(t *testing.T) {
	rows := analyzeSpamMessages([]quarantineSpamMessage{
		{EnvelopeSender: "first@example.com", From: "First <first@example.com>", Subject: "Same"},
		{EnvelopeSender: "second@example.com", From: "Second <second@example.com>", Subject: "Same"},
		{EnvelopeSender: "third@example.com", From: "Third <third@example.com>", Subject: "Same"},
		{EnvelopeSender: "first@example.com", From: "First <first@example.com>", Subject: "Other"},
		{EnvelopeSender: "second@example.com", From: "Second <second@example.com>", Subject: "Other"},
	}, 3, nil)

	want := []spamAnalysisRow{
		{
			Subject:  "Same",
			Count:    3,
			Script:   "latin",
			Language: "unknown",
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "first@example.com", From: "First <first@example.com>", Count: 1, Action: "skip"},
				{EnvelopeSender: "second@example.com", From: "Second <second@example.com>", Count: 1, Action: "skip"},
				{EnvelopeSender: "third@example.com", From: "Third <third@example.com>", Count: 1, Action: "skip"},
			},
		},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got rows %#v, want %#v", rows, want)
	}
}

func TestAnalyzeWritesRows(t *testing.T) {
	var out bytes.Buffer
	err := analyze(context.Background(), DaemonConfig{
		Timeout: time.Minute,
		Rules: Rules{
			{
				Name:   "Delete sender",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"envelope_sender": {`^sender@example\.com$`}}},
			},
			{
				Name:   "Deliver other",
				Action: quarantineActionDeliver,
				When:   RuleGroups{{"envelope_sender": {`^other@example\.com$`}}},
			},
		},
	}, 2, &out, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{EnvelopeSender: "sender@example.com", From: "Sender <sender@example.com>", Subject: "Weekly air shipment documents are ready for review"},
			{EnvelopeSender: "sender@example.com", From: "Sender <sender@example.com>", Subject: "Weekly air shipment documents are ready for review"},
			{EnvelopeSender: "other@example.com", From: "Other <other@example.com>", Subject: "Weekly air shipment documents are ready for review"},
			{EnvelopeSender: "other@example.com", From: "Other <other@example.com>", Subject: "Other"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"Weekly air shipment documents are ready for review - 3 - latin - en",
		"sender@example.com - Sender <sender@example.com> - 2 - delete",
		"other@example.com - Other <other@example.com> - 1 - deliver",
	}, "\n")
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("got output %q", out.String())
	}
}

func TestAnalyzeWritesActionsWithCountCondition(t *testing.T) {
	var out bytes.Buffer
	err := analyze(context.Background(), DaemonConfig{
		Timeout: time.Minute,
		Rules: Rules{
			{
				Name:   "Delete repeated subject",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"subject": {`^Repeated$`}, "count": {"2"}}},
			},
			{
				Name:   "Delete rare subject",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"subject": {`^Rare$`}, "count": {"2"}}},
			},
		},
	}, 1, &out, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{EnvelopeSender: "sender@example.com", From: "Sender <sender@example.com>", Subject: "Repeated"},
			{EnvelopeSender: "other@example.com", From: "Other <other@example.com>", Subject: "Repeated"},
			{EnvelopeSender: "rare@example.com", From: "Rare <rare@example.com>", Subject: "Rare"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"sender@example.com - Sender <sender@example.com> - 1 - delete",
		"other@example.com - Other <other@example.com> - 1 - delete",
		"rare@example.com - Rare <rare@example.com> - 1 - skip",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestAnalyzeSpamJSONWritesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spam.json")
	data := `200 OK
[{"envelope_sender":"sender@example.com","from":"Sender <sender@example.com>","subject":"Уведомление о поступлении новых электронных документов"},{"envelope_sender":"sender@example.com","from":"Sender <sender@example.com>","subject":"Уведомление о поступлении новых электронных документов"},{"envelope_sender":"other@example.com","from":"Other <other@example.com>","subject":"Other"}]
done`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := AnalyzeSpamJSON(context.Background(), DaemonConfig{Timeout: time.Minute}, path, 2, &out); err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"Уведомление о поступлении новых электронных документов - 2 - cyrillic - ru",
		"sender@example.com - Sender <sender@example.com> - 2 - skip",
	}, "\n")
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("got output %q", out.String())
	}
}

func TestAnalyzeValidatesTimeout(t *testing.T) {
	err := Analyze(context.Background(), DaemonConfig{Timeout: 0}, 1, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}
