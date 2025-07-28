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
