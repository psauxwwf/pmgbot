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
		{ID: "same-b-1", EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Subject: "Same"},
		{ID: "same-a-1", EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", Subject: "Same"},
		{ID: "other-b-1", EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Subject: "Other"},
		{ID: "same-b-2", EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", Subject: "Same"},
		{ID: "other-a-1", EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", Subject: "Other"},
		{ID: "other-a-2", EnvelopeSender: "a@example.com", From: "Other Alpha <a@example.com>", Subject: "Other"},
		{ID: "same-c-1", EnvelopeSender: "c@example.com", From: "Charlie <c@example.com>", Subject: "Same"},
	}, 1, nil)

	want := []spamAnalysisRow{
		{
			Subject:  "Same",
			Count:    4,
			Script:   "latin",
			Language: "unknown",
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", IDs: []string{"same-b-1", "same-b-2"}, Count: 2, Action: "skip"},
				{EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", IDs: []string{"same-a-1"}, Count: 1, Action: "skip"},
				{EnvelopeSender: "c@example.com", From: "Charlie <c@example.com>", IDs: []string{"same-c-1"}, Count: 1, Action: "skip"},
			},
		},
		{
			Subject:  "Other",
			Count:    3,
			Script:   "latin",
			Language: "en",
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "a@example.com", From: "Alpha <a@example.com>", IDs: []string{"other-a-1"}, Count: 1, Action: "skip"},
				{EnvelopeSender: "a@example.com", From: "Other Alpha <a@example.com>", IDs: []string{"other-a-2"}, Count: 1, Action: "skip"},
				{EnvelopeSender: "b@example.com", From: "Beta <b@example.com>", IDs: []string{"other-b-1"}, Count: 1, Action: "skip"},
			},
		},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got rows %#v, want %#v", rows, want)
	}
}

func TestAnalyzeSpamMessagesFiltersBySubjectMinCount(t *testing.T) {
	rows := analyzeSpamMessages([]quarantineSpamMessage{
		{ID: "same-1", EnvelopeSender: "first@example.com", From: "First <first@example.com>", Subject: "Same"},
		{ID: "same-2", EnvelopeSender: "second@example.com", From: "Second <second@example.com>", Subject: "Same"},
		{ID: "same-3", EnvelopeSender: "third@example.com", From: "Third <third@example.com>", Subject: "Same"},
		{ID: "other-1", EnvelopeSender: "first@example.com", From: "First <first@example.com>", Subject: "Other"},
		{ID: "other-2", EnvelopeSender: "second@example.com", From: "Second <second@example.com>", Subject: "Other"},
	}, 3, nil)

	want := []spamAnalysisRow{
		{
			Subject:  "Same",
			Count:    3,
			Script:   "latin",
			Language: "unknown",
			Senders: []spamAnalysisSenderRow{
				{EnvelopeSender: "first@example.com", From: "First <first@example.com>", IDs: []string{"same-1"}, Count: 1, Action: "skip"},
				{EnvelopeSender: "second@example.com", From: "Second <second@example.com>", IDs: []string{"same-2"}, Count: 1, Action: "skip"},
				{EnvelopeSender: "third@example.com", From: "Third <third@example.com>", IDs: []string{"same-3"}, Count: 1, Action: "skip"},
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
			{ID: "delete-1", EnvelopeSender: "sender@example.com", From: "Sender <sender@example.com>", Subject: "Weekly air shipment documents are ready for review"},
			{ID: "delete-2", EnvelopeSender: "sender@example.com", From: "Sender <sender@example.com>", Subject: "Weekly air shipment documents are ready for review"},
			{ID: "deliver-1", EnvelopeSender: "other@example.com", From: "Other <other@example.com>", Subject: "Weekly air shipment documents are ready for review"},
			{ID: "deliver-2", EnvelopeSender: "other@example.com", From: "Other <other@example.com>", Subject: "Other"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"Weekly air shipment documents are ready for review | 3 | latin | en",
		"sender@example.com | Sender <sender@example.com> | [delete-1,delete-2] | 2 | [delete:Delete sender]",
		"other@example.com | Other <other@example.com> | [deliver-1] | 1 | [deliver:Deliver other]",
		"---",
		"summary | total: 4 | deliver: 2 | delete: 2 | remain: 0",
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
				Name:   "Delete repeated subjects",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"subject": {sameValuePattern}, "count": {"2"}}},
			},
		},
	}, 1, &out, func(context.Context) ([]quarantineSpamMessage, error) {
		return []quarantineSpamMessage{
			{ID: "repeated-1", EnvelopeSender: "sender@example.com", From: "Sender <sender@example.com>", Subject: "Repeated"},
			{ID: "repeated-2", EnvelopeSender: "other@example.com", From: "Other <other@example.com>", Subject: "Repeated"},
			{ID: "rare-1", EnvelopeSender: "rare@example.com", From: "Rare <rare@example.com>", Subject: "Rare"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{
		"sender@example.com | Sender <sender@example.com> | [repeated-1] | 1 | [delete:Delete repeated subjects]",
		"other@example.com | Other <other@example.com> | [repeated-2] | 1 | [delete:Delete repeated subjects]",
		"rare@example.com | Rare <rare@example.com> | [rare-1] | 1 | skip",
		"summary | total: 3 | deliver: 0 | delete: 2 | remain: 1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestAnalyzeSpamJSONWritesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spam.json")
	data := `200 OK
[{"id":"json-1","envelope_sender":"sender@example.com","from":"Sender <sender@example.com>","subject":"Уведомление о поступлении новых электронных документов"},{"id":"json-2","envelope_sender":"sender@example.com","from":"Sender <sender@example.com>","subject":"Уведомление о поступлении новых электронных документов"},{"id":"json-3","envelope_sender":"other@example.com","from":"Other <other@example.com>","subject":"Other"}]
done`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := AnalyzeSpamJSON(context.Background(), DaemonConfig{Timeout: time.Minute}, path, 2, &out); err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"Уведомление о поступлении новых электронных документов | 2 | cyrillic | ru",
		"sender@example.com | Sender <sender@example.com> | [json-1,json-2] | 2 | skip",
		"---",
		"summary | total: 3 | deliver: 0 | delete: 0 | remain: 3",
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
