# Testing

## Running

```sh
go test ./...
go run ./scripts/check
```

## Policy

The test file referenced by the README is `k8smanifestsecurity_test.go`; it contains `ExampleScan`, a runnable example verified by `go test` through its `// Output:` comment. Tests exercise the public API and assert returned findings, sentinel errors (`ErrInputTooLarge`, `ErrInvalidYAML`, `ErrTooManyDocuments`) and CLI exit codes.

The acceptance cases cover:

- a privileged Pod returning K001, K004, K005, K006, K007 and K009 with severity and path;
- a compliant Deployment returning no findings;
- K008 for a missing tag, `latest` and registry ports, and no K008 for a tag or `sha256` digest;
- K006 capability add and the `NET_BIND_SERVICE` exception;
- Deployment `hostNetwork`, `hostPath`, CronJob paths and `hostPort`;
- document indexing, `MaxBytes`, alias rejection, depth 64 and `MaxDocuments`;
- `Run` JSON output, exit codes 0, 1 and 2, and `Options.Disabled`.

## Tiers

- Local tier: `go test ./...` runs the public-API tests and the runnable example.
- The repository gate program `scripts/check` runs the test suite as part of the documented gates.

## Layout

`k8smanifestsecurity_test.go` sits at the module root next to the library files.
