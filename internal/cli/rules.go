package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.dw1.io/x/exp/sandboxec/access"
)

type fsRule struct {
	Rights access.FS
	Path   string
}

type networkRule struct {
	Rights access.Network
	Port   uint16
}

type fsRulesValue struct {
	rules []fsRule
}

func (v *fsRulesValue) String() string {
	if v == nil || len(v.rules) == 0 {
		return ""
	}
	out := make([]string, 0, len(v.rules))
	for _, rule := range v.rules {
		text, _ := marshalFSRule(rule)
		out = append(out, text)
	}
	return strings.Join(out, ",")
}

func (v *fsRulesValue) Set(s string) error {
	rule, err := parseFSRule(s)
	if err != nil {
		return err
	}
	v.rules = append(v.rules, rule)
	return nil
}

func (v *fsRulesValue) Type() string {
	return "RIGHTS:PATH"
}

func (v *fsRulesValue) Slice() []fsRule {
	return append([]fsRule(nil), v.rules...)
}

type networkRulesValue struct {
	rules []networkRule
}

func (v *networkRulesValue) String() string {
	if v == nil || len(v.rules) == 0 {
		return ""
	}
	out := make([]string, 0, len(v.rules))
	for _, rule := range v.rules {
		text, _ := marshalNetworkRule(rule)
		out = append(out, text)
	}
	return strings.Join(out, ",")
}

func (v *networkRulesValue) Set(s string) error {
	rule, err := parseNetworkRule(s)
	if err != nil {
		return err
	}
	v.rules = append(v.rules, rule)
	return nil
}

func (v *networkRulesValue) Type() string {
	return "RIGHTS:PORT"
}

func (v *networkRulesValue) Slice() []networkRule {
	return append([]networkRule(nil), v.rules...)
}

func parseFSRule(value string) (fsRule, error) {
	rightsText, path, ok := strings.Cut(value, ":")
	if !ok {
		return fsRule{}, fmt.Errorf("expected RIGHTS:PATH")
	}
	if strings.TrimSpace(path) == "" {
		return fsRule{}, errors.New("path is empty")
	}

	rights, err := parseFSRights(rightsText)
	if err != nil {
		return fsRule{}, err
	}

	expandedPath, err := expandFSPath(path)
	if err != nil {
		return fsRule{}, err
	}

	return fsRule{Rights: rights, Path: expandedPath}, nil
}

func expandFSPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	expanded := os.ExpandEnv(trimmed)

	if expanded == "~" || strings.HasPrefix(expanded, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("cannot expand ~: HOME is not set")
		}
		if expanded == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(expanded, "~/")), nil
	}

	return expanded, nil
}

func marshalFSRule(rule fsRule) (string, error) {
	rights, err := marshalFSRights(rule.Rights)
	if err != nil {
		return "", err
	}
	return rights + ":" + rule.Path, nil
}

func parseNetworkRule(value string) (networkRule, error) {
	rightsText, portText, ok := strings.Cut(value, ":")
	if !ok {
		return networkRule{}, fmt.Errorf("expected RIGHTS:PORT")
	}

	rights, err := parseNetworkRights(rightsText)
	if err != nil {
		return networkRule{}, err
	}

	portNumber, err := strconv.ParseUint(strings.TrimSpace(portText), 10, 16)
	if err != nil {
		return networkRule{}, fmt.Errorf("invalid port %q", portText)
	}

	return networkRule{Rights: rights, Port: uint16(portNumber)}, nil
}

func marshalNetworkRule(rule networkRule) (string, error) {
	rights, err := marshalNetworkRights(rule.Rights)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", rights, rule.Port), nil
}

func parseFSRights(s string) (access.FS, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read", "r":
		return access.FS_READ, nil
	case "read_exec", "rx":
		return access.FS_READ_EXEC, nil
	case "write", "w":
		return access.FS_WRITE, nil
	case "read_write", "rw":
		return access.FS_READ_WRITE, nil
	case "read_write_exec", "rwx":
		return access.FS_READ_WRITE_EXEC, nil
	default:
		return 0, fmt.Errorf("invalid fs rights %q (valid: read|r, read_exec|rx, write|w, read_write|rw, read_write_exec|rwx)", s)
	}
}

func marshalFSRights(rights access.FS) (string, error) {
	switch rights {
	case access.FS_READ:
		return "r", nil
	case access.FS_READ_EXEC:
		return "rx", nil
	case access.FS_WRITE:
		return "w", nil
	case access.FS_READ_WRITE:
		return "rw", nil
	case access.FS_READ_WRITE_EXEC:
		return "rwx", nil
	default:
		return "", fmt.Errorf("unknown fs rights %d", rights)
	}
}

func parseNetworkRights(s string) (access.Network, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bind", "b":
		return access.NETWORK_BIND_TCP, nil
	case "connect", "c":
		return access.NETWORK_CONNECT_TCP, nil
	case "bind_connect", "bc", "cb":
		return access.NETWORK_BIND_TCP | access.NETWORK_CONNECT_TCP, nil
	default:
		return 0, fmt.Errorf("invalid network rights %q (valid: bind|b, connect|c, bind_connect|bc)", s)
	}
}

func marshalNetworkRights(rights access.Network) (string, error) {
	all := access.NETWORK_BIND_TCP | access.NETWORK_CONNECT_TCP
	switch rights {
	case access.NETWORK_BIND_TCP:
		return "b", nil
	case access.NETWORK_CONNECT_TCP:
		return "c", nil
	case all:
		return "bc", nil
	default:
		return "", fmt.Errorf("unknown network rights %d", rights)
	}
}
