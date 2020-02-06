package terminal

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-colorable"
	"golang.org/x/crypto/ssh/terminal"
)

const minWidth = 60
const maxWidth = 80

// Terminal handles interacting with the user in Certigo
type Terminal interface {
	Output() io.Writer
	Error() io.Writer
	SetDefaultPassword(password string)
	ReadPassword(prompt string) string
	DetermineWidth() int
}

// TTY represents unixish stdio, possibly with /dev/tty used to read user input
type TTY struct {
	defaultPassword *string
}

func OpenTTY() *TTY {
	return &TTY{}
}

func (t *TTY) Output() io.Writer {
	return colorable.NewColorableStdout()
}

func (t *TTY) Error() io.Writer {
	return os.Stderr
}

func (t *TTY) SetDefaultPassword(password string) {
	t.defaultPassword = &password
}

func (t *TTY) ReadPassword(prompt string) string {
	if t.defaultPassword != nil {
		return *t.defaultPassword
	}

	var tty *os.File
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	tty.WriteString("Enter password")
	if prompt != "" {
		tty.WriteString(fmt.Sprintf(" for entry [%s]", prompt))
	}
	tty.WriteString(": ")

	password, err := terminal.ReadPassword(int(tty.Fd()))
	tty.WriteString("\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %s\n", err)
		os.Exit(1)
	}

	return strings.TrimSuffix(string(password), "\n")
}

func (t *TTY) DetermineWidth() int {
	var width int
	fd := int(os.Stdout.Fd())
	if terminal.IsTerminal(fd) {
		var err error
		width, _, err = terminal.GetSize(fd)
		if err != nil {
			width = minWidth
		}
	} else {
		width = minWidth
	}

	if width > maxWidth {
		width = maxWidth
	} else if width < minWidth {
		width = minWidth
	}
	return width
}

// Assert TTY implements terminal
var _ Terminal = &TTY{}
