package pmgbot

import (
	"strings"
	"testing"
)

func TestPMGQuarantineSpamFromOutput(t *testing.T) {
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

	messages, err := pmgQuarantineSpamFromOutput(out)
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

func TestPMGQuarantineSpamFromOutputIgnoresLeadingStatus(t *testing.T) {
	messages, err := pmgQuarantineSpamFromOutput([]byte("200 OK\n[{\"id\":\"C1\"}]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].ID != "C1" {
		t.Fatalf("got messages %#v", messages)
	}
}

func TestPMGQuarantineSpamFromOutputIgnoresTrailingStatus(t *testing.T) {
	messages, err := pmgQuarantineSpamFromOutput([]byte("[{\"id\":\"C1\"}]\n200 OK"))
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].ID != "C1" {
		t.Fatalf("got messages %#v", messages)
	}
}

func TestPMGQuarantineSpamFromOutputReturnsError(t *testing.T) {
	_, err := pmgQuarantineSpamFromOutput([]byte("200 OK"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCompileFieldPatternsReturnsRegexError(t *testing.T) {
	_, err := compileFieldPatterns("delete", FieldPatterns{"subject": {"["}})
	if err == nil {
		t.Fatal("expected regexp error")
	}
	if !strings.Contains(err.Error(), `compile delete pattern for field "subject"`) {
		t.Fatalf("got error %q", err)
	}
}

func TestCompileFieldPatternsReturnsUnknownFieldError(t *testing.T) {
	_, err := compileFieldPatterns("delete", FieldPatterns{"sender": {`.*`}})
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), `unknown delete field "sender"`) {
		t.Fatalf("got error %q", err)
	}
}

func TestCompileFieldPatternsReturnsUnknownNumericFieldError(t *testing.T) {
	_, err := compileFieldPatterns("delete", FieldPatterns{"bytes": {`^0$`}})
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), `unknown delete field "bytes"`) {
		t.Fatalf("got error %q", err)
	}
}

func TestCompileFieldPatternsIgnoresEmptyFields(t *testing.T) {
	compiled, err := compileFieldPatterns("delete", FieldPatterns{
		"bytes":     nil,
		"id":        {},
		"spamlevel": {"", " "},
		"time":      nil,
		"sender":    nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 0 {
		t.Fatalf("got compiled patterns %#v, want empty", compiled)
	}
}

func TestDecideQuarantineAction(t *testing.T) {
	rules, err := compileRules(Rules{
		{
			Name:   "Deliver trusted",
			Action: quarantineActionDeliver,
			When: RuleGroups{
				{"envelope_sender": {`^trusted@example\.com$`}},
				{"subject": {`(?i)allow`}},
			},
		},
		{
			Name:   "Delete bad",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{"envelope_sender": {`@bad\.ru$`}},
				{"subject": {`(?i)casino`}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		message quarantineSpamMessage
		want    quarantineAction
		wantOK  bool
	}{
		{
			name: "deliver",
			message: quarantineSpamMessage{
				EnvelopeSender: "trusted@example.com",
			},
			want:   quarantineActionDeliver,
			wantOK: true,
		},
		{
			name: "delete",
			message: quarantineSpamMessage{
				EnvelopeSender: "spam@bad.ru",
			},
			want:   quarantineActionDelete,
			wantOK: true,
		},
		{
			name: "first matching rule wins",
			message: quarantineSpamMessage{
				EnvelopeSender: "trusted@example.com",
				Subject:        "casino",
			},
			want:   quarantineActionDeliver,
			wantOK: true,
		},
		{
			name: "missing field",
			message: quarantineSpamMessage{
				Receiver: "user@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := decideQuarantineAction(tt.message, rules)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("got %q/%v, want %q/%v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestDecideQuarantineActionRequiresAllFieldsInRuleGroup(t *testing.T) {
	rules, err := compileRules(Rules{
		{
			Name:   "Delete webmaster registration",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{
					"envelope_sender": {`^webmaster@rc\.ffff\.ru$`},
					"subject":         {`^\[SPAM\]: Зарегистрировался новый пользователь$`},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		message quarantineSpamMessage
		wantOK  bool
	}{
		{
			name: "all fields match",
			message: quarantineSpamMessage{
				EnvelopeSender: "webmaster@rc.ffff.ru",
				Subject:        "[SPAM]: Зарегистрировался новый пользователь",
			},
			wantOK: true,
		},
		{
			name: "only sender matches",
			message: quarantineSpamMessage{
				EnvelopeSender: "webmaster@rc.ffff.ru",
				Subject:        "[SPAM]: Other",
			},
		},
		{
			name: "only subject matches",
			message: quarantineSpamMessage{
				EnvelopeSender: "other@example.com",
				Subject:        "[SPAM]: Зарегистрировался новый пользователь",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := decideQuarantineAction(tt.message, rules)
			if ok != tt.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tt.wantOK)
			}
			if ok && got != quarantineActionDelete {
				t.Fatalf("got action %q, want delete", got)
			}
		})
	}
}

func TestDecideQuarantineActionMatchesPatternListAsOr(t *testing.T) {
	rules, err := compileRules(Rules{
		{
			Name:   "Delete webmaster notifications",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{
					"envelope_sender": {`^webmaster@rc\.ffff\.ru$`},
					"subject": {
						`^\[SPAM\]: Зарегистрировался новый пользователь$`,
						`^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$`,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		message quarantineSpamMessage
		wantOK  bool
	}{
		{
			name: "registration",
			message: quarantineSpamMessage{
				EnvelopeSender: "webmaster@rc.ffff.ru",
				Subject:        "[SPAM]: Зарегистрировался новый пользователь",
			},
			wantOK: true,
		},
		{
			name: "payment",
			message: quarantineSpamMessage{
				EnvelopeSender: "webmaster@rc.ffff.ru",
				Subject:        "[SPAM]: Платеж 123 на сумму 456 руб. подтвержден",
			},
			wantOK: true,
		},
		{
			name: "different subject",
			message: quarantineSpamMessage{
				EnvelopeSender: "webmaster@rc.ffff.ru",
				Subject:        "[SPAM]: Other",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ruleName, ok := decideQuarantineAction(tt.message, rules)
			if ok != tt.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tt.wantOK)
			}
			if ok && (got != quarantineActionDelete || ruleName != "Delete webmaster notifications") {
				t.Fatalf("got action %q rule %q, want delete rule name", got, ruleName)
			}
		})
	}
}

func TestCompileRulesValidatesAction(t *testing.T) {
	_, err := compileRules(Rules{{Name: "Bad action", Action: "archive", When: RuleGroups{{"subject": {`.*`}}}}})
	if err == nil {
		t.Fatal("expected action validation error")
	}
	if !strings.Contains(err.Error(), `invalid action "archive"`) {
		t.Fatalf("got error %q", err)
	}
}

func TestQuarantineSpamID(t *testing.T) {
	tests := []struct {
		name    string
		message quarantineSpamMessage
		want    string
		wantErr bool
	}{
		{name: "string", message: quarantineSpamMessage{ID: " C1 "}, want: "C1"},
		{name: "missing", message: quarantineSpamMessage{}, wantErr: true},
		{name: "empty", message: quarantineSpamMessage{ID: " "}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := quarantineSpamID(tt.message)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompileFieldPatternsDeduplicates(t *testing.T) {
	compiled, err := compileFieldPatterns("deliver", FieldPatterns{"subject": {"test", "test", " "}})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled["subject"]) != 1 {
		t.Fatalf("got %d patterns, want 1", len(compiled["subject"]))
	}
}
