package lang

import "testing"

func TestSubjectScript(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{name: "latin", subject: "Weekly Air shipment documents", want: "latin"},
		{name: "cyrillic", subject: "Уведомление 1С-ЭДО", want: "cyrillic"},
		{name: "spam latin", subject: "[SPAM]: Weekly Air shipment", want: "latin"},
		{name: "spam cyrillic", subject: "[SPAM]: Уведомление 1С-ЭДО", want: "cyrillic"},
		{name: "cjk", subject: "重要なお知らせ", want: "cjk"},
		{name: "mixed", subject: "Hello Привет", want: "mixed"},
		{name: "emoji only", subject: "💥🔥 123", want: "unknown"},
		{name: "empty", subject: " ", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SubjectScript(tt.subject); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSubjectLanguage(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{
			name:    "english",
			subject: "Weekly air shipment documents are ready for review and confirmation",
			want:    "en",
		},
		{
			name:    "russian",
			subject: "Уведомление о поступлении новых электронных документов",
			want:    "ru",
		},
		{
			name:    "spanish",
			subject: "Solicitud de cotizacion para suministro urgente de materiales",
			want:    "es",
		},
		{name: "spam prefix", subject: "[SPAM]: Weekly air shipment documents are ready for review", want: "en"},
		{name: "empty", subject: "", want: "unknown"},
		{name: "emoji only", subject: "💥🔥 123", want: "unknown"},
		{name: "too short", subject: "ok", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SubjectLanguage(tt.subject); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
