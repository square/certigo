# gen-known-logs

A tool for generating the list of CT logs that certigo uses for printing operator information and log URLs for SCTs.

Logs are fetched and parsed from https://www.gstatic.com/ct/log_list/v3/all_logs_list.json, documented [here](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md). The list includes both RFC 6962 logs and static-ct-api ("tiled") logs. For a tiled log, certigo shows its submission URL.

The v3 list drops logs after they expire. The tool keeps every log that is already in `lib/ctlogs.go`, so that SCTs in older certificates still show their log operator.

## Usage

Run `go generate ./lib` to regenerate known logs.
