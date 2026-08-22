package pmgbot

import (
	"strings"
	"testing"
)

func TestCompileFieldPatternsReturnsRegexError(t *testing.T) {
	_, err := compileFieldPatterns("delete", FieldPatterns{"subject": {"["}})
	if err == nil {
		t.Fatal("expected regexp error")
	}
	if !strings.Contains(err.Error(), `compile delete pattern for field "subject"`) {
		t.Fatalf("got error %q", err)
	}
}

func TestCompileFieldPatternsReturnsRegexErrorForInvertedPattern(t *testing.T) {
	_, err := compileFieldPatterns("delete", FieldPatterns{"subject": {"[!]["}})
	if err == nil {
		t.Fatal("expected regexp error")
	}
	if !strings.Contains(err.Error(), `compile delete pattern for field "subject" "[!]["`) {
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

func TestCompileRulesAcceptsCountCondition(t *testing.T) {
	rules, err := compileRules(Rules{{
		Name:   "Delete repeated test subjects",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {`^TEST$`}, "count": {"3"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].When[0].Count.Operator != countEqualOrGreater || rules[0].When[0].Count.Value != 3 {
		t.Fatalf("got count %#v, want >=3", rules[0].When[0].Count)
	}
}

func TestCompileRulesAcceptsSameValuePattern(t *testing.T) {
	rules, err := compileRules(Rules{{
		Name:   "Delete repeated subjects",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {sameValuePattern}, "count": {"3"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !rules[0].When[0].Patterns["subject"][0].Same {
		t.Fatalf("got patterns %#v, want same value pattern", rules[0].When[0].Patterns)
	}
}

func TestCompileRulesAcceptsCountOperators(t *testing.T) {
	tests := []struct {
		name         string
		count        string
		wantOperator countOperator
		wantValue    int
	}{
		{name: "greater", count: ">3", wantOperator: countGreater, wantValue: 3},
		{name: "less", count: "<3", wantOperator: countLess, wantValue: 3},
		{name: "greater or equal", count: ">=3", wantOperator: countEqualOrGreater, wantValue: 3},
		{name: "less or equal", count: "<=3", wantOperator: countEqualOrLess, wantValue: 3},
		{name: "spaces", count: ">= 3", wantOperator: countEqualOrGreater, wantValue: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := compileRules(Rules{{
				Name:   "Delete repeated test subjects",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"subject": {`^TEST$`}, "count": {tt.count}}},
			}})
			if err != nil {
				t.Fatal(err)
			}

			got := rules[0].When[0].Count
			if got.Operator != tt.wantOperator || got.Value != tt.wantValue {
				t.Fatalf("got count %#v, want %s%d", got, tt.wantOperator, tt.wantValue)
			}
		})
	}
}

func TestCompileRulesRejectsInvalidCountCondition(t *testing.T) {
	_, err := compileRules(Rules{{
		Name:   "Bad count",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {`^TEST$`}, "count": {"nope"}}},
	}})
	if err == nil {
		t.Fatal("expected invalid count error")
	}
	if !strings.Contains(err.Error(), `Bad count count must be a single integer with optional comparison operator`) {
		t.Fatalf("got error %q", err)
	}
}

func TestCompileRulesRejectsCountBelowMinimum(t *testing.T) {
	_, err := compileRules(Rules{{
		Name:   "Bad count",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {`^TEST$`}, "count": {"0"}}},
	}})
	if err == nil {
		t.Fatal("expected invalid count error")
	}
	if !strings.Contains(err.Error(), `Bad count count must be at least 1`) {
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

func TestCompileFieldPatternsAcceptsComputedSubjectFields(t *testing.T) {
	compiled, err := compileFieldPatterns("delete", FieldPatterns{
		"subject_script":   {`^latin$`},
		"subject_language": {`^en$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled["subject_script"]) != 1 {
		t.Fatalf("got %d subject_script patterns, want 1", len(compiled["subject_script"]))
	}
	if len(compiled["subject_language"]) != 1 {
		t.Fatalf("got %d subject_language patterns, want 1", len(compiled["subject_language"]))
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

func TestDecideQuarantineActionMatchesComputedSubjectFields(t *testing.T) {
	rules, err := compileRules(Rules{
		{
			Name:   "Delete latin subject",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{
					"envelope_sender": {`^spam@example\.com$`},
					"subject_script":  {`^latin$`},
				},
			},
		},
		{
			Name:   "Delete english subject",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{"subject_language": {`^en$`}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		message  quarantineSpamMessage
		wantOK   bool
		wantRule string
	}{
		{
			name: "script and sender",
			message: quarantineSpamMessage{
				EnvelopeSender: "spam@example.com",
				Subject:        "[SPAM]: Weekly Air shipment",
			},
			wantOK:   true,
			wantRule: "Delete latin subject",
		},
		{
			name: "language",
			message: quarantineSpamMessage{
				EnvelopeSender: "other@example.com",
				Subject:        "Weekly air shipment documents are ready for review and confirmation",
			},
			wantOK:   true,
			wantRule: "Delete english subject",
		},
		{
			name: "script group requires sender",
			message: quarantineSpamMessage{
				EnvelopeSender: "other@example.com",
				Subject:        "Short latin text",
			},
		},
		{
			name: "cyrillic does not match",
			message: quarantineSpamMessage{
				EnvelopeSender: "spam@example.com",
				Subject:        "Уведомление о поступлении документов",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ruleName, ok := decideQuarantineAction(tt.message, rules)
			if ok != tt.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tt.wantOK)
			}
			if ruleName != tt.wantRule {
				t.Fatalf("got rule %q, want %q", ruleName, tt.wantRule)
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

func TestDecideQuarantineActionMatchesInvertedPattern(t *testing.T) {
	rules, err := compileRules(Rules{
		{
			Name:   "Delete English but not delivery notifications",
			Action: quarantineActionDelete,
			When: RuleGroups{
				{
					"subject_script":   {`^latin$`},
					"subject_language": {`^en$`},
					"subject":          {`[!]Mail Delivery`},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		subject string
		wantOK  bool
	}{
		{name: "does not contain excluded text", subject: "Weekly air shipment documents are ready for review", wantOK: true},
		{name: "contains excluded text", subject: "Mail Delivery Subsystem: Delivery Status Notification"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, ok := decideQuarantineAction(quarantineSpamMessage{Subject: tt.subject}, rules)
			if ok != tt.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestDecideQuarantineActionMatchesCountCondition(t *testing.T) {
	rules, err := compileRules(Rules{
		{
			Name:   "Delete repeated test subjects",
			Action: quarantineActionDelete,
			When:   RuleGroups{{"subject": {`^TEST$`}, "count": {"3"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	messages := []quarantineSpamMessage{
		{ID: "1", Subject: "TEST"},
		{ID: "2", Subject: "TEST"},
		{ID: "3", Subject: "TEST"},
		{ID: "4", Subject: "OTHER"},
	}
	got, ruleName, ok := decideQuarantineActionForMessages(messages[0], messages, rules)
	if !ok || got != quarantineActionDelete || ruleName != "Delete repeated test subjects" {
		t.Fatalf("got action %q rule %q ok %v", got, ruleName, ok)
	}

	_, _, ok = decideQuarantineActionForMessages(messages[3], messages, rules)
	if ok {
		t.Fatal("expected different subject not to match")
	}

	_, _, ok = decideQuarantineActionForMessages(messages[0], messages[:2], rules)
	if ok {
		t.Fatal("expected repeated subject below count not to match")
	}
}

func TestDecideQuarantineActionMatchesCountOperators(t *testing.T) {
	messages := []quarantineSpamMessage{
		{ID: "1", Subject: "TEST"},
		{ID: "2", Subject: "TEST"},
		{ID: "3", Subject: "TEST"},
		{ID: "4", Subject: "OTHER"},
	}
	tests := []struct {
		name  string
		count string
		want  bool
	}{
		{name: "greater", count: ">2", want: true},
		{name: "greater false", count: ">3"},
		{name: "less", count: "<4", want: true},
		{name: "less false", count: "<3"},
		{name: "greater or equal", count: ">=3", want: true},
		{name: "greater or equal false", count: ">=4"},
		{name: "less or equal", count: "<=3", want: true},
		{name: "less or equal false", count: "<=2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := compileRules(Rules{{
				Name:   "Delete repeated test subjects",
				Action: quarantineActionDelete,
				When:   RuleGroups{{"subject": {`^TEST$`}, "count": {tt.count}}},
			}})
			if err != nil {
				t.Fatal(err)
			}

			_, _, ok := decideQuarantineActionForMessages(messages[0], messages, rules)
			if ok != tt.want {
				t.Fatalf("got ok %v, want %v", ok, tt.want)
			}
		})
	}
}

func TestDecideQuarantineActionMatchesSameSubjectCount(t *testing.T) {
	rules, err := compileRules(Rules{{
		Name:   "Delete repeated subjects",
		Action: quarantineActionDelete,
		When:   RuleGroups{{"subject": {sameValuePattern}, "count": {"3"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	messages := []quarantineSpamMessage{
		{ID: "1", Subject: "Repeated"},
		{ID: "2", Subject: "Repeated"},
		{ID: "3", Subject: "Repeated"},
		{ID: "4", Subject: "Rare"},
		{ID: "5", Subject: "Rare"},
	}

	got, ruleName, ok := decideQuarantineActionForMessages(messages[0], messages, rules)
	if !ok || got != quarantineActionDelete || ruleName != "Delete repeated subjects" {
		t.Fatalf("got action %q rule %q ok %v", got, ruleName, ok)
	}

	_, _, ok = decideQuarantineActionForMessages(messages[3], messages, rules)
	if ok {
		t.Fatal("expected subject repeated only twice not to match")
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
