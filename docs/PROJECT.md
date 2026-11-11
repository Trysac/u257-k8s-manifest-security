# Project record

## Objective

Check Kubernetes workload manifests against Pod Security Standards baseline and restricted controls plus image and memory limit hygiene, with exact field paths and stable rule codes.

## Scope

In scope:

- The Go library `k8smanifestsecurity` with `Scan`, `Run`, `Options`, `Finding` and the sentinel errors.
- Parsing multi-document YAML for Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job and CronJob workloads; checking `containers` and `initContainers`.
- Rules K001–K010: privileged containers, host namespaces, hostPath volumes, privilege escalation, non-root, capabilities, seccomp, image tags, memory limits and host ports.
- Text and JSON CLI output, `--disable`, files or stdin, and exit codes 0, 1 and 2.
- Input limits: `MaxBytes` default `4_194_304`, `MaxDocuments` default `1000`, alias rejection and nesting depth 64.

Out of scope:

- Helm or Kustomize rendering.
- Live clusters and admission control.
- NetworkPolicy and RBAC checks.
- AppArmor and SELinux controls.
- Ephemeral containers.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 874637 / 79498 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.0992 |

## Factory run u257 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-11 | generation | deepseek-v4-pro | yes | 3884 | 26473 | 0 | 1280 | 0.0550 |
| 2026-11-11 | fix-1 | deepseek-flash | no | 20315 | 10482 | 0 | 182016 | 0.0099 |
| 2026-11-11 | audit | deepseek-flash | no | 23978 | 15204 | 0 | 230400 | 0.0134 |
| 2026-11-11 | fix-2 | deepseek-flash | no | 17798 | 17686 | 0 | 390400 | 0.0145 |
| 2026-11-11 | docs | deepseek-flash | no | 4182 | 9653 | 0 | 384 | 0.0064 |

Total: $0.0992. Prices: deepseek line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
