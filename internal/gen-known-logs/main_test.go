// Copyright 2026 Block, Inc.
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

package main

import (
	"bytes"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testLogList = `{
  "version": "1.2",
  "log_list_timestamp": "2026-10-26T13:45:16Z",
  "operators": [
    {
      "name": "Google",
      "logs": [{"log_id": "classic=", "url": "https://ct.example/classic/"}],
      "tiled_logs": [{
        "log_id": "tiled=",
        "submission_url": "https://ct.example/submit/",
        "monitoring_url": "https://ct.example/monitor/"
      }]
    },
    {"name": "Empty"}
  ]
}`

func serveLogList(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFetchLogList(t *testing.T) {
	list, err := fetchLogList(serveLogList(t, http.StatusOK, testLogList))
	if err != nil {
		t.Fatal(err)
	}
	if list.Version != "1.2" || list.Timestamp != "2026-10-26T13:45:16Z" {
		t.Errorf("version %q, timestamp %q", list.Version, list.Timestamp)
	}

	want := map[string]ctLog{
		"classic=": {operator: "Google", url: "https://ct.example/classic/"},
		"tiled=":   {operator: "Google", url: "https://ct.example/submit/"},
	}
	if got := list.knownLogs(); !maps.Equal(got, want) {
		t.Errorf("knownLogs() = %v, want %v", got, want)
	}
}

func TestFetchLogListHTTPError(t *testing.T) {
	if _, err := fetchLogList(serveLogList(t, http.StatusNotFound, "<html>Not Found</html>")); err == nil {
		t.Fatal("fetchLogList succeeded on a 404")
	}
}

func TestReadKnownLogsMissingFile(t *testing.T) {
	logs, err := readKnownLogs(filepath.Join(t.TempDir(), "ctlogs.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 {
		t.Errorf("readKnownLogs() = %v, want no logs", logs)
	}
}

func TestWriteThenReadKnownLogs(t *testing.T) {
	want := map[string]ctLog{
		"b=": {operator: "Let's Encrypt", url: "https://oak.ct.letsencrypt.org/2025h1/"},
		"a=": {operator: `Quote " and \ backslash`, url: "https://ct.example/"},
	}
	var buf bytes.Buffer
	if err := writeKnownLogs(&buf, "lib", &logList{Version: "1.2", Timestamp: "now"}, want); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ctlogs.go")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readKnownLogs(path)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, want) {
		t.Errorf("readKnownLogs() = %v, want %v", got, want)
	}
}

// The next regeneration keeps the logs that lib/ctlogs.go has now, so it must
// stay readable.
func TestReadCheckedInKnownLogs(t *testing.T) {
	logs, err := readKnownLogs("../../lib/ctlogs.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("no logs in lib/ctlogs.go")
	}
	for id, l := range logs {
		if l.operator == "" || l.url == "" {
			t.Errorf("log %s has operator %q and URL %q", id, l.operator, l.url)
		}
	}
}
