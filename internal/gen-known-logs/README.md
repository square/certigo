# gen-known-logs

A tool for generating the list of CT logs that certigo uses for printing operator information and log URLs for SCTs.

Logs are fetched parsed from https://www.gstatic.com/ct/log_list/v2/all_logs_list.json, documented [here](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md).

## Usage

From the current directory (`certigo/internal/gen-known-logs`), run `make ctlogs`. This will fetch the list of logs and place generated code in [lib/ctlogs.go](../../lib/ctlogs.go).