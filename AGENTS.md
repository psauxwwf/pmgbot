# Project Instructions

- Avoid `map[string]struct{}` for set-like checks; prefer slices with `slices.Contains`.
- Rule patterns in YAML config use Go `regexp` syntax, which is RE2 regular expression syntax.
