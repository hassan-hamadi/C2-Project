package funcs

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// splitDiagnosticArgs splits a raw command string into a binary name and argument
// slice. Double and single quotes are respected so that quoted strings are
// treated as a single token. Escaped quotes inside a quoted string are also
// handled. The first token is the binary name; the remainder are the args.
func splitDiagnosticArgs(command string) (string, []string) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", nil
	}

	var tokens []string
	var current strings.Builder
	inDouble := false
	inSingle := false
	inToken := false

	for i := 0; i < len(command); i++ {
		c := command[i]

		switch {
		case inDouble:
			if c == '\\' && i+1 < len(command) && command[i+1] == '"' {
				// Escaped double-quote inside double-quoted string
				current.WriteByte('"')
				i++
			} else if c == '"' {
				inDouble = false
			} else {
				current.WriteByte(c)
			}

		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				current.WriteByte(c)
			}

		case c == '"':
			inDouble = true
			inToken = true

		case c == '\'':
			inSingle = true
			inToken = true

		case c == ' ' || c == '\t':
			if inToken {
				tokens = append(tokens, current.String())
				current.Reset()
				inToken = false
			}

		default:
			current.WriteByte(c)
			inToken = true
		}
	}

	if inToken {
		tokens = append(tokens, current.String())
	}

	if len(tokens) == 0 {
		return "", nil
	}

	binary := tokens[0]
	args := tokens[1:]
	return binary, args
}

// RunDiagnosticProbe runs a command without a shell. The binary is resolved
// via exec.LookPath and arguments are passed directly, so shell metacharacters
// are treated as literal argument strings (no pipes, redirects, or chaining).
func RunDiagnosticProbe(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("empty command")
	}

	binary, args := splitDiagnosticArgs(command)
	if binary == "" {
		return "", fmt.Errorf("empty command")
	}

	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("%s: executable not found in PATH", binary)
	}

	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = CurrentDir
	setHideWindow(cmd)

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output) + fmt.Sprintf("\n[TIMEOUT] Command killed after %s", CommandTimeout), fmt.Errorf("command timed out after %s", CommandTimeout)
	}

	if err != nil {
		return string(output) + "\n" + err.Error(), err
	}

	return string(output), nil
}