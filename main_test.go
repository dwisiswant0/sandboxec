package main

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"testing"
)

type exitPanic struct {
	code int
}

func TestMain_SuccessNoExit(t *testing.T) {
	prevRunCLI := runCLI
	prevExitProcess := exitProc
	prevStderr := stderr
	prevArgs := os.Args
	t.Cleanup(func() {
		runCLI = prevRunCLI
		exitProc = prevExitProcess
		stderr = prevStderr
		os.Args = prevArgs
	})

	var gotArgs []string
	var stderrBuf bytes.Buffer
	stderr = &stderrBuf
	os.Args = []string{"sandboxec", "--", "echo", "ok"}

	runCLI = func(args []string) (int, error) {
		gotArgs = append([]string(nil), args...)
		return 0, nil
	}
	exitProc = func(code int) {
		panic(exitPanic{code: code})
	}

	main()

	wantArgs := []string{"--", "echo", "ok"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("main passed args %v, want %v", gotArgs, wantArgs)
	}
	if got := stderrBuf.String(); got != "" {
		t.Fatalf("unexpected stderr output: %q", got)
	}
}

func TestMain_ErrorExitsOne(t *testing.T) {
	prevRunCLI := runCLI
	prevExitProcess := exitProc
	prevStderr := stderr
	prevArgs := os.Args
	t.Cleanup(func() {
		runCLI = prevRunCLI
		exitProc = prevExitProcess
		stderr = prevStderr
		os.Args = prevArgs
	})

	var stderrBuf bytes.Buffer
	stderr = &stderrBuf
	os.Args = []string{"sandboxec"}

	runCLI = func(args []string) (int, error) {
		return 0, errors.New("boom")
	}
	exitProc = func(code int) {
		panic(exitPanic{code: code})
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected process exit")
		}
		exit, ok := r.(exitPanic)
		if !ok {
			t.Fatalf("unexpected panic value: %T", r)
		}
		if exit.code != 1 {
			t.Fatalf("exit code %d, want 1", exit.code)
		}
		if got := stderrBuf.String(); got != "sandboxec: boom\n" {
			t.Fatalf("stderr %q, want %q", got, "sandboxec: boom\\n")
		}
	}()

	main()
}

func TestMain_PropagatesNonZeroExitCode(t *testing.T) {
	prevRunCLI := runCLI
	prevExitProcess := exitProc
	prevStderr := stderr
	prevArgs := os.Args
	t.Cleanup(func() {
		runCLI = prevRunCLI
		exitProc = prevExitProcess
		stderr = prevStderr
		os.Args = prevArgs
	})

	var stderrBuf bytes.Buffer
	stderr = &stderrBuf
	os.Args = []string{"sandboxec"}

	runCLI = func(args []string) (int, error) {
		return 23, nil
	}
	exitProc = func(code int) {
		panic(exitPanic{code: code})
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected process exit")
		}
		exit, ok := r.(exitPanic)
		if !ok {
			t.Fatalf("unexpected panic value: %T", r)
		}
		if exit.code != 23 {
			t.Fatalf("exit code %d, want 23", exit.code)
		}
		if got := stderrBuf.String(); got != "" {
			t.Fatalf("unexpected stderr output: %q", got)
		}
	}()

	main()
}

func TestMain_ErrorTakesPrecedenceOverExitCode(t *testing.T) {
	prevRunCLI := runCLI
	prevExitProcess := exitProc
	prevStderr := stderr
	prevArgs := os.Args
	t.Cleanup(func() {
		runCLI = prevRunCLI
		exitProc = prevExitProcess
		stderr = prevStderr
		os.Args = prevArgs
	})

	var stderrBuf bytes.Buffer
	stderr = &stderrBuf
	os.Args = []string{"sandboxec", "--help"}

	runCLI = func(args []string) (int, error) {
		return 42, errors.New("run failed")
	}
	exitProc = func(code int) {
		panic(exitPanic{code: code})
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected process exit")
		}
		exit, ok := r.(exitPanic)
		if !ok {
			t.Fatalf("unexpected panic value: %T", r)
		}
		if exit.code != 1 {
			t.Fatalf("exit code %d, want 1", exit.code)
		}
		if got := stderrBuf.String(); got != "sandboxec: run failed\n" {
			t.Fatalf("stderr %q, want %q", got, "sandboxec: run failed\\n")
		}
	}()

	main()
}

func TestMain_ForwardsEmptyArgsWhenNoCLIArgs(t *testing.T) {
	prevRunCLI := runCLI
	prevExitProcess := exitProc
	prevStderr := stderr
	prevArgs := os.Args
	t.Cleanup(func() {
		runCLI = prevRunCLI
		exitProc = prevExitProcess
		stderr = prevStderr
		os.Args = prevArgs
	})

	var gotArgs []string
	var stderrBuf bytes.Buffer
	stderr = &stderrBuf
	os.Args = []string{"sandboxec"}

	runCLI = func(args []string) (int, error) {
		gotArgs = append([]string(nil), args...)
		return 0, nil
	}
	exitProc = func(code int) {
		panic(exitPanic{code: code})
	}

	main()

	if gotArgs == nil {
		gotArgs = []string{}
	}
	if !reflect.DeepEqual(gotArgs, []string{}) {
		t.Fatalf("main passed args %v, want empty args", gotArgs)
	}
	if got := stderrBuf.String(); got != "" {
		t.Fatalf("unexpected stderr output: %q", got)
	}
}
