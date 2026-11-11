# Security

## Defended

The library treats YAML input as untrusted. It enforces:

- Input size: `Options.MaxBytes`, default `4_194_304` bytes; larger input returns `ErrInputTooLarge`.
- Document count: `Options.MaxDocuments`, default `1000`; more returns `ErrTooManyDocuments`.
- YAML aliases: alias nodes are rejected and return `ErrInvalidYAML`, preventing billion-laughs expansion.
- Nesting depth: deeper than 64 returns `ErrInvalidYAML`, preventing stack exhaustion.
- Booleans: YAML 1.2 core schema; quoted `true`/`false` are strings.
- Error text: sentinel errors are wrapped with `%w`; messages include the document index and line and at most 200 characters of input.

No network access or external services are used. The CLI reads only local files or stdin.

## Not defended

- Helm and Kustomize rendering are not performed.
- Live cluster state and admission control are not contacted.
- NetworkPolicy and RBAC are not checked.
- AppArmor and SELinux controls are not checked.
- Ephemeral containers are not inspected.
- Image contents, image vulnerabilities and registry access are not checked.
- The process itself is not sandboxed; it relies on the input limits above.
