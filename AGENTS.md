# Project Instructions

- Avoid `map[string]struct{}` for set-like checks; prefer slices with `slices.Contains`.
- Rule patterns in YAML config use Go `regexp` syntax, which is RE2 regular expression syntax.
- Prefixing a YAML rule pattern with `[!]` inverts that individual regexp; quote such YAML values, for example `subject: '[!]Mail Delivery'`.
