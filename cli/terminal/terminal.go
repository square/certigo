// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package terminal

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-colorable"
	"golang.org/x/crypto/ssh/terminal" //nolint:staticcheck // TODO: Change dependencies when upgrading to Go >= 1.17
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
		defer func() { _ = tty.Close() }()
	}

	_, _ = tty.WriteString("Enter password")
	if prompt != "" {
		_, _ = fmt.Fprintf(tty, " for entry [%s]", prompt)
	}
	_, _ = tty.WriteString(": ")

	password, err := terminal.ReadPassword(int(tty.Fd()))
	_, _ = tty.WriteString("\n")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error reading password: %s\n", err)
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
