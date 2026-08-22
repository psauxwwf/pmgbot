package pmg

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQuarantineSpamArgsUsesThirtyDayWindow(t *testing.T) {
	now := time.Unix(1785764932, 0)
	args := quarantineSpamArgs(now)

	if len(args) != 6 {
		t.Fatalf("got args %#v, want 6 args", args)
	}
	if args[0] != "get" || args[1] != "/quarantine/spam" || args[2] != "--starttime" || args[4] != "--endtime" {
		t.Fatalf("got args %#v", args)
	}

	starttime, err := strconv.ParseInt(args[3], 10, 64)
	if err != nil {
		t.Fatalf("parse starttime: %v", err)
	}
	endtime, err := strconv.ParseInt(args[5], 10, 64)
	if err != nil {
		t.Fatalf("parse endtime: %v", err)
	}

	if starttime != now.AddDate(0, 0, -quarantineSpamLookbackDays).Unix() {
		t.Fatalf("got starttime %d", starttime)
	}
	if endtime != now.Unix() {
		t.Fatalf("got endtime %d", endtime)
	}
}

func TestQuarantineSpamFromOutput(t *testing.T) {
	out := []byte(`[
  {
    "bytes": 23678,
    "envelope_sender": "2@eko-sunkey.ru",
    "from": "Sender <2@eko-sunkey.ru>",
    "id": "C3R1659121T226340378",
    "receiver": "user@example.com",
    "spamlevel": 8,
    "subject": "[SPAM]: Test",
    "time": 1785764932
  }
]`)

	messages, err := quarantineSpamFromOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(messages))
	}
	if messages[0].ID != "C3R1659121T226340378" {
		t.Fatalf("got id %v", messages[0].ID)
	}
	if messages[0].EnvelopeSender != "2@eko-sunkey.ru" {
		t.Fatalf("got envelope sender %v", messages[0].EnvelopeSender)
	}
	if messages[0].SpamLevel != 8 {
		t.Fatalf("got spamlevel %v", messages[0].SpamLevel)
	}
	if messages[0].Bytes != 23678 {
		t.Fatalf("got bytes %v", messages[0].Bytes)
	}
	if messages[0].Time != 1785764932 {
		t.Fatalf("got time %v", messages[0].Time)
	}
}

func TestQuarantineSpamFromOutputIgnoresLeadingStatus(t *testing.T) {
	messages, err := quarantineSpamFromOutput([]byte("200 OK\n[{\"id\":\"C1\"}]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].ID != "C1" {
		t.Fatalf("got messages %#v", messages)
	}
}

func TestQuarantineSpamFromOutputIgnoresTrailingStatus(t *testing.T) {
	messages, err := quarantineSpamFromOutput([]byte("[{\"id\":\"C1\"}]\n200 OK"))
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].ID != "C1" {
		t.Fatalf("got messages %#v", messages)
	}
}

func TestQuarantineSpamFromOutputReturnsError(t *testing.T) {
	_, err := quarantineSpamFromOutput([]byte("200 OK"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestQuarantineContentFromOutput(t *testing.T) {
	out := []byte(`200 OK
{
  "bytes": 34185,
  "content": "body",
  "envelope_sender": "sender@example.com",
  "file": "cluster/1/spam/05/8852F06A89C7AACF305",
  "from": "Sender <sender@example.com>",
  "header": "Return-Path: sender@example.com\n",
  "id": "C1R1691568T97183293",
  "receiver": "user@example.com",
  "spaminfo": [
    {"desc": "Bayes spam probability is 0 to 1%", "name": "BAYES_00", "score": -1.9},
    {"desc": "Headers contain an unresolved template", "name": "UNRESOLVED_TEMPLATE", "score": 1.252}
  ],
  "spamlevel": 5,
  "subject": "[SPAM]: Test",
  "time": 1787414437
}
200 OK`)

	content, err := quarantineContentFromOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if content.ID != "C1R1691568T97183293" {
		t.Fatalf("got id %q", content.ID)
	}
	if content.File != "cluster/1/spam/05/8852F06A89C7AACF305" {
		t.Fatalf("got file %q", content.File)
	}
	if content.Header != "Return-Path: sender@example.com\n" {
		t.Fatalf("got header %q", content.Header)
	}
	if content.SpamLevel != 5 || content.Bytes != 34185 || content.Time != 1787414437 {
		t.Fatalf("got content %#v", content)
	}
	if len(content.SpamInfo) != 2 {
		t.Fatalf("got spaminfo %#v", content.SpamInfo)
	}
	if content.SpamInfo[0].Name != "BAYES_00" || content.SpamInfo[0].Score != -1.9 {
		t.Fatalf("got spaminfo %#v", content.SpamInfo)
	}
	if content.Raw != "" {
		t.Fatalf("parser must not fill raw, got %q", content.Raw)
	}
}

func TestQuarantineRawFromFile(t *testing.T) {
	root := t.TempDir()
	file := "cluster/1/spam/05/8852F06A89C7AACF305"
	path := filepath.Join(root, file)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("raw message"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := quarantineRawFromFile(root, file)
	if err != nil {
		t.Fatal(err)
	}
	if raw != "raw message" {
		t.Fatalf("got raw %q", raw)
	}
}

func TestQuarantineRawFromFileRejectsUnsafePath(t *testing.T) {
	for _, file := range []string{"", "/tmp/message", "../message", "cluster/../../message"} {
		_, err := quarantineRawFromFile(t.TempDir(), file)
		if err == nil {
			t.Fatalf("expected error for %q", file)
		}
	}
}

func TestQuarantineContentFromOutputReturnsError(t *testing.T) {
	_, err := quarantineContentFromOutput([]byte("200 OK"))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("got error %q", err)
	}
}
