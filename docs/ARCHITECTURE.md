# Architecture

The scanner is a small Go library with a thin CLI wrapper. The core algorithm is:

1. Read the entire input into memory up to `Options.MaxBytes` (default 4 MiB).
2. Decode the YAML stream document by document into `yaml.Node` trees without expanding aliases.
3. Reject alias nodes and nesting deeper than 64 before any semantic analysis.
4. For each document whose root is a mapping with a known workload `kind`, walk the pod spec (respecting the nesting for Deployment, CronJob, etc.).
5. Evaluate each rule against the pod spec and containers, building `Finding` values with exact field paths.
6. Sort findings by document index, path and rule code.

The CLI (`cmd/k8s-manifest-security`) delegates to `Run`, which handles flag parsing, file opening and output formatting.

## Rule design

Rules K001–K010 map directly to Pod Security Standards controls and common image/memory hygiene checks. Boolean values follow YAML 1.2 core schema: only unquoted `true` and `false` are recognised, preventing YAML 1.1 gotchas like `yes`/`no`/`on`/`off`.
