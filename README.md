# k8s-manifest-security

`k8smanifestsecurity` is a Go library and command-line tool that checks Kubernetes workload manifests against Pod Security Standards baseline and restricted controls, plus image and memory limit hygiene. It reports each violation with a stable rule code, severity and the exact field path to fix.

## Features

- Parses multi-document YAML with input size, document count, alias and nesting-depth limits.
- Supports Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job and CronJob workloads.
- Checks both `containers` and `initContainers`.
- Rule codes K001–K010: K001–K007 and K010 follow Pod Security Standards baseline/restricted controls; K008–K009 cover image and memory hygiene.
- Output as human-readable text or structured JSON.
- Disable individual rules with `--disable`.

## Installation

```sh
go install github.com/Trysac/u257-k8s-manifest-security/cmd/k8s-manifest-security@latest
```

## Usage (library)

```go
package main
import (
 "fmt"
 "strings"
 k8smanifestsecurity "github.com/Trysac/u257-k8s-manifest-security"
)
func main() {
 f, _ := k8smanifestsecurity.Scan(strings.NewReader("kind: Pod\n"), k8smanifestsecurity.Options{})
 fmt.Println(len(f))
}
```

`ExampleScan` in [k8smanifestsecurity_test.go](k8smanifestsecurity_test.go) contains the runnable example with its verified `// Output:` listing.

## Public API

- `type Options struct { MaxBytes int; MaxDocuments int; Disabled []string }`. `MaxBytes` defaults to `4_194_304` and `MaxDocuments` to `1000` when zero. `Disabled` lists rule codes to skip.
- `type Finding struct { Rule, Severity, Kind, Name, Container, Path, Message string; Document int }`. JSON tags are `rule`, `severity`, `kind`, `name`, `container`, `path`, `message`, `document`. `Document` is the zero-based document index.
- `func Scan(r io.Reader, opts Options) ([]Finding, error)`.
- `func Run(args []string, stdout, stderr io.Writer) int`.
- Sentinel errors `ErrInputTooLarge`, `ErrInvalidYAML` and `ErrTooManyDocuments` are wrapped with `fmt.Errorf` `%w`; messages carry the document index and line and never more than 200 characters of input.

Findings are sorted by document, path and rule. Unknown kinds and empty documents are skipped.

## Limits and errors

Inputs over `Options.MaxBytes` return `ErrInputTooLarge`. More than `Options.MaxDocuments` documents return `ErrTooManyDocuments`. YAML aliases and nesting deeper than 64 return `ErrInvalidYAML`. Booleans follow YAML 1.2 core schema: only unquoted `true` and `false` are recognised.

## CLI

```sh
k8s-manifest-security --format json pod.yaml
k8s-manifest-security --disable K009,K008 manifest.yaml
```

- `--format text|json` selects the output format (default `text`).
- `--disable` accepts a comma-separated list of rule codes to skip.
- Files or `-` for stdin are accepted; multiple files are scanned in sequence.
- Exit codes: `0` no findings, `1` findings present, `2` error.

## Why not kube-score or Polaris

This repository provides a small embeddable Go library with Pod Security Standards-named rule codes and exact field paths. It checks the runtime pod spec in a manifest; it does not render Helm or Kustomize, connect to a cluster, or audit Dockerfiles.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Decisions](docs/decisions/)
