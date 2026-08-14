package lang

import (
	"strings"
	"unicode"

	lingua "github.com/pemistahl/lingua-go"
)

const unknown = "unknown"

var subjectLanguageDetector = lingua.NewLanguageDetectorBuilder().
	FromAllLanguages().
	WithMinimumRelativeDistance(0.1).
	Build()

// SubjectScript returns the dominant writing system used by subject letters.
func SubjectScript(subject string) string {
	subject = normalizeSubject(subject)

	var latin, cyrillic, cjk, other int
	for _, r := range subject {
		if !unicode.IsLetter(r) {
			continue
		}

		switch {
		case unicode.In(r, unicode.Latin):
			latin++
		case unicode.In(r, unicode.Cyrillic):
			cyrillic++
		case unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul):
			cjk++
		default:
			other++
		}
	}

	total := latin + cyrillic + cjk + other
	if total == 0 {
		return unknown
	}
	if isDominant(latin, total) {
		return "latin"
	}
	if isDominant(cyrillic, total) {
		return "cyrillic"
	}
	if isDominant(cjk, total) {
		return "cjk"
	}

	return "mixed"
}

// SubjectLanguage returns the ISO 639-1 language code detected from subject.
func SubjectLanguage(subject string) string {
	subject = normalizeSubject(subject)
	if !hasLetters(subject) {
		return unknown
	}

	language, ok := subjectLanguageDetector.DetectLanguageOf(subject)
	if !ok {
		return unknown
	}

	code := language.IsoCode639_1()
	if code == lingua.UnknownIsoCode639_1 {
		return unknown
	}

	return strings.ToLower(code.String())
}

func normalizeSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if strings.HasPrefix(strings.ToUpper(subject), "[SPAM]:") {
		subject = strings.TrimSpace(subject[len("[SPAM]:"):])
	}

	return subject
}

func isDominant(count int, total int) bool {
	return count*100 >= total*80
}

func hasLetters(text string) bool {
	for _, r := range text {
		if unicode.IsLetter(r) {
			return true
		}
	}

	return false
}
