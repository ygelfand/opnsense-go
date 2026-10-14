package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Int64 decodes integer API fields represented as JSON numbers or decimal strings.
type Int64 int64

// UnmarshalJSON accepts an integer while preserving its full signed precision.
func (n *Int64) UnmarshalJSON(data []byte) error {
	text := string(bytes.TrimSpace(data))
	if len(text) > 0 && text[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer API field: %w", err)
	}
	*n = Int64(value)
	return nil
}
