package cli

import (
	"fmt"
	"strings"
)

type modeValue struct {
	value string
}

func (m *modeValue) Set(s string) error {
	v := strings.ToLower(strings.TrimSpace(s))
	if v != "run" && v != "mcp" {
		return fmt.Errorf("invalid mode %q (valid: run|mcp)", s)
	}
	m.value = v
	return nil
}

func (m *modeValue) String() string {
	if m == nil || m.value == "" {
		return "run"
	}
	return m.value
}

func (m *modeValue) Type() string {
	return "run|mcp"
}

func (m *modeValue) Value() string {
	if m == nil || m.value == "" {
		return "run"
	}
	return m.value
}
