package pmg

import "testing"

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
