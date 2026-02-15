package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.dw1.io/x/exp/sandboxec"
)

type Config struct {
	Name        string
	Version     string
	Description string
	Options     []sandboxec.Option
}

type input struct {
	Command string   `json:"command" jsonschema:"command to execute (e.g., /bin/echo)"`
	Args    []string `json:"args,omitempty" jsonschema:"arguments for command (optional)"`
}

type output struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func handler(Options []sandboxec.Option) mcp.ToolHandlerFor[input, output] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input input) (*mcp.CallToolResult, output, error) {
		out, err := run(ctx, input, Options)
		if err != nil {
			return nil, output{}, err
		}

		return &mcp.CallToolResult{}, out, nil
	}
}

func run(ctx context.Context, input input, Options []sandboxec.Option) (output, error) {
	if input.Command == "" {
		return output{}, fmt.Errorf("command is required")
	}

	opts := append([]sandboxec.Option(nil), Options...)
	sb := sandboxec.New(opts...)
	cmd := sb.Command(input.Command, input.Args...)
	if cmd.Err != nil {
		return output{}, cmd.Err
	}
	if ctx != nil {
		go func() {
			<-ctx.Done()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}()
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := output{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err == nil {
		out.ExitCode = 0
		return out, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		out.ExitCode = exitErr.ExitCode()
		return out, nil
	}

	return output{}, fmt.Errorf("run command: %w", err)
}

func Serve(ctx context.Context, cfg Config) error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    cfg.Name,
		Version: cfg.Version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "exec",
		Description: "Execute a command and return stdout, stderr, and exit code.",
	}, handler(cfg.Options))

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("run mcp server: %w", err)
	}

	return nil
}
