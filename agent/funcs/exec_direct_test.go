package funcs

import (
	"reflect"
	"testing"
)

func Test_splitDiagnosticArgs(t *testing.T) {
	tests := []struct {
		input          string
		expectedBinary string
		expectedArgs   []string
	}{
		{
			input:          "whoami",
			expectedBinary: "whoami",
			expectedArgs:   nil,
		},
		{
			input:          "net user admin /domain",
			expectedBinary: "net",
			expectedArgs:   []string{"user", "admin", "/domain"},
		},
		{
			input:          `findstr "hello world" file.txt`,
			expectedBinary: "findstr",
			expectedArgs:   []string{"hello world", "file.txt"},
		},
		{
			input:          "  whoami  ",
			expectedBinary: "whoami",
			expectedArgs:   nil,
		},
		{
			input:          "",
			expectedBinary: "",
			expectedArgs:   nil,
		},
		{
			input:          "echo 'hello world' file",
			expectedBinary: "echo",
			expectedArgs:   []string{"hello world", "file"},
		},
		{
			input:          `C:\Windows\System32\whoami.exe`,
			expectedBinary: `C:\Windows\System32\whoami.exe`,
			expectedArgs:   nil,
		},
		{
			input:          `"C:\Program Files\app.exe" --flag`,
			expectedBinary: `C:\Program Files\app.exe`,
			expectedArgs:   []string{"--flag"},
		},
		{
			input:          `echo "" test`,
			expectedBinary: "echo",
			expectedArgs:   []string{"", "test"},
		},
		{
			input:          `echo "say \"hi\""`,
			expectedBinary: "echo",
			expectedArgs:   []string{`say "hi"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotBinary, gotArgs := splitDiagnosticArgs(tt.input)

			if gotBinary != tt.expectedBinary {
				t.Errorf("binary: got %q, want %q", gotBinary, tt.expectedBinary)
			}

			if !reflect.DeepEqual(gotArgs, tt.expectedArgs) {
				t.Errorf("args: got %v, want %v", gotArgs, tt.expectedArgs)
			}
		})
	}
}