# Use yaml.v3 Node API for safe, spec-compliant YAML processing

Status: accepted (generated, pending human review)

## Context

The scanner must parse multi-document YAML and evaluate Pod Security Standards rules on pod specs. It must enforce limits (size, documents, alias rejection, depth) and follow YAML 1.2 core boolean semantics.

## Decision

Use go.yaml.in/yaml/v3 to decode into yaml.Node structures rather than mapping directly to typed structs. Walk the Node tree manually, applying custom checks for boolean values (only unquoted true/false), integer parsing, and path construction. Reject alias nodes and enforce a depth limit of 64 before rule evaluation.

## Consequences

Pros: precise control over field paths, easy rejection of unsupported constructs, ability to handle diverse workload kinds without struct tags. Cons: more verbose code than struct-based decoding, and manual validation needed for security limits. The dependency is pinned to v3.0.4.
