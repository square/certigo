package terminal

import (
	"bytes"
	"io"

	"github.com/mattn/go-colorable"
)

// TestTerminal just collects input into buffers
// That can be used to check output in tests
type TestTerminal struct {
	OutputBuf bytes.Buffer
	ErrorBuf  bytes.Buffer
	Password  string
	Width     int
}

var _ Terminal = &TestTerminal{}

func (t *TestTerminal) Output() io.Writer {
	return colorable.NewNonColorable(&t.OutputBuf)
}

func (t *TestTerminal) Error() io.Writer {
	return &t.ErrorBuf
}

func (t *TestTerminal) SetDefaultPassword(password string) {
	t.Password = password
}

func (t *TestTerminal) ReadPassword(prompt string) string {
	return t.Password
}

func (t TestTerminal) DetermineWidth() int {
	return t.Width
}
