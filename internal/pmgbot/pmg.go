package pmgbot

import (
	"encoding/json"
	"fmt"
	"strings"
)

func decodePMGJSONArray(out []byte, v any) error {
	text := strings.TrimSpace(string(out))
	jsonStart := strings.Index(text, "[")
	if jsonStart == -1 {
		return fmt.Errorf("pmgsh output does not contain JSON array")
	}

	decoder := json.NewDecoder(strings.NewReader(text[jsonStart:]))
	if err := decoder.Decode(v); err != nil {
		return err
	}

	return nil
}
