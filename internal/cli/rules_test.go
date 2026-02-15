package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
)

func TestParseFSRights_Aliases(t *testing.T) {
	tests := []struct {
		in   string
		want access.FS
	}{
		{"read", access.FS_READ},
		{"r", access.FS_READ},
		{"read_exec", access.FS_READ_EXEC},
		{"rx", access.FS_READ_EXEC},
		{"write", access.FS_WRITE},
		{"w", access.FS_WRITE},
		{"read_write", access.FS_READ_WRITE},
		{"rw", access.FS_READ_WRITE},
		{"read_write_exec", access.FS_READ_WRITE_EXEC},
		{"rwx", access.FS_READ_WRITE_EXEC},
		{"  RWX  ", access.FS_READ_WRITE_EXEC},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseFSRights(tt.in)
			if err != nil {
				t.Fatalf("parseFSRights(%q) returned error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseFSRights(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseFSRights_Invalid(t *testing.T) {
	_, err := parseFSRights("execute")
	if err == nil {
		t.Fatal("expected error for invalid fs rights")
	}
	if !strings.Contains(err.Error(), "valid:") {
		t.Fatalf("expected valid rights hint, got: %v", err)
	}
}

func TestParseFSRule_EdgeCases(t *testing.T) {
	if _, err := parseFSRule("rw:/tmp"); err != nil {
		t.Fatalf("expected valid fs rule, got: %v", err)
	}
	if _, err := parseFSRule("rw:"); err == nil {
		t.Fatal("expected empty path error")
	}
	if _, err := parseFSRule("rw"); err == nil {
		t.Fatal("expected missing separator error")
	}
}

func TestParseFSRule_ExpandsEnvAndTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ruleFromEnv, err := parseFSRule("rw:$HOME/.claude/")
	if err != nil {
		t.Fatalf("expected env-based fs rule to parse, got: %v", err)
	}
	wantEnvPath := filepath.Join(home, ".claude") + "/"
	if ruleFromEnv.Path != wantEnvPath {
		t.Fatalf("env expansion mismatch: got %q, want %q", ruleFromEnv.Path, wantEnvPath)
	}

	ruleFromTilde, err := parseFSRule("rw:~/.claude.json")
	if err != nil {
		t.Fatalf("expected tilde-based fs rule to parse, got: %v", err)
	}
	wantTildePath := filepath.Join(home, ".claude.json")
	if ruleFromTilde.Path != wantTildePath {
		t.Fatalf("tilde expansion mismatch: got %q, want %q", ruleFromTilde.Path, wantTildePath)
	}
}

func TestParseFSRule_ExpandsPWD(t *testing.T) {
	pwd := t.TempDir()
	t.Setenv("PWD", pwd)

	rule, err := parseFSRule("rw:$PWD")
	if err != nil {
		t.Fatalf("expected PWD-based fs rule to parse, got: %v", err)
	}
	if rule.Path != pwd {
		t.Fatalf("PWD expansion mismatch: got %q, want %q", rule.Path, pwd)
	}
}

func TestParseNetworkRights_Aliases(t *testing.T) {
	all := access.NETWORK_BIND_TCP | access.NETWORK_CONNECT_TCP
	tests := []struct {
		in   string
		want access.Network
	}{
		{"bind", access.NETWORK_BIND_TCP},
		{"b", access.NETWORK_BIND_TCP},
		{"connect", access.NETWORK_CONNECT_TCP},
		{"c", access.NETWORK_CONNECT_TCP},
		{"bind_connect", all},
		{"bc", all},
		{"cb", all},
		{"  BC  ", all},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseNetworkRights(tt.in)
			if err != nil {
				t.Fatalf("parseNetworkRights(%q) returned error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseNetworkRights(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseNetworkRule_PortBoundaries(t *testing.T) {
	r0, err := parseNetworkRule("c:0")
	if err != nil {
		t.Fatalf("expected port 0 to parse, got: %v", err)
	}
	if r0.Port != 0 {
		t.Fatalf("expected port 0, got: %d", r0.Port)
	}

	rMax, err := parseNetworkRule("c:65535")
	if err != nil {
		t.Fatalf("expected port 65535 to parse, got: %v", err)
	}
	if rMax.Port != 65535 {
		t.Fatalf("expected port 65535, got: %d", rMax.Port)
	}

	if _, err := parseNetworkRule("c:65536"); err == nil {
		t.Fatal("expected out-of-range port error")
	}
	if _, err := parseNetworkRule("c:-1"); err == nil {
		t.Fatal("expected negative port error")
	}
	if _, err := parseNetworkRule("c:not-a-port"); err == nil {
		t.Fatal("expected non-numeric port error")
	}
	if _, err := parseNetworkRule("c"); err == nil {
		t.Fatal("expected missing separator error")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	rule, err := parseFSRule("rw:/tmp")
	if err != nil {
		t.Fatalf("parseFSRule failed: %v", err)
	}
	out, err := marshalFSRule(rule)
	if err != nil {
		t.Fatalf("marshalFSRule failed: %v", err)
	}
	if out != "rw:/tmp" {
		t.Fatalf("marshalFSRule got %q, want %q", out, "rw:/tmp")
	}

	nr, err := parseNetworkRule("bc:443")
	if err != nil {
		t.Fatalf("parseNetworkRule failed: %v", err)
	}
	nout, err := marshalNetworkRule(nr)
	if err != nil {
		t.Fatalf("marshalNetworkRule failed: %v", err)
	}
	if nout != "bc:443" {
		t.Fatalf("marshalNetworkRule got %q, want %q", nout, "bc:443")
	}
}

func TestRulesValue_Accumulates(t *testing.T) {
	var fsv fsRulesValue
	if err := fsv.Set("r:/etc"); err != nil {
		t.Fatalf("set fs rule 1: %v", err)
	}
	if err := fsv.Set("rw:/tmp"); err != nil {
		t.Fatalf("set fs rule 2: %v", err)
	}
	if len(fsv.Slice()) != 2 {
		t.Fatalf("expected 2 fs rules, got %d", len(fsv.Slice()))
	}

	var nsv networkRulesValue
	if err := nsv.Set("c:443"); err != nil {
		t.Fatalf("set network rule 1: %v", err)
	}
	if err := nsv.Set("b:8080"); err != nil {
		t.Fatalf("set network rule 2: %v", err)
	}
	if len(nsv.Slice()) != 2 {
		t.Fatalf("expected 2 network rules, got %d", len(nsv.Slice()))
	}
}
