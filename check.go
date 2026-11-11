package k8smanifestsecurity

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// checkWorkload inspects a single Kubernetes document (root mapping) and
// returns all applicable findings. Non-workload kinds and empty documents are
// skipped.
func checkWorkload(root *yaml.Node, docIndex int, disabled map[string]bool) []Finding {
	kind := scalarString(mapValue(root, "kind"))
	if kind == "" {
		return nil
	}
	name := scalarString(mapValue(mapValue(root, "metadata"), "name"))

	var podSpec *yaml.Node
	var prefix string

	switch kind {
	case "Pod":
		podSpec = mapValue(root, "spec")
		prefix = "spec"
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		spec := mapValue(root, "spec")
		template := mapValue(spec, "template")
		podSpec = mapValue(template, "spec")
		prefix = "spec.template.spec"
	case "CronJob":
		spec := mapValue(root, "spec")
		jobTemplate := mapValue(spec, "jobTemplate")
		jobSpec := mapValue(jobTemplate, "spec")
		template := mapValue(jobSpec, "template")
		podSpec = mapValue(template, "spec")
		prefix = "spec.jobTemplate.spec.template.spec"
	default:
		return nil
	}
	if podSpec == nil {
		return nil
	}

	podSecCtx := mapValue(podSpec, "securityContext")
	var findings []Finding

	add := func(rule, severity, path, container, msg string) {
		if disabled[rule] {
			return
		}
		findings = append(findings, Finding{
			Rule:      rule,
			Severity:  severity,
			Kind:      kind,
			Name:      name,
			Container: container,
			Path:      path,
			Message:   msg,
			Document:  docIndex,
		})
	}

	// K002: host namespace usage (one finding per field).
	for _, field := range []struct {
		key  string
		path string
	}{
		{"hostNetwork", "hostNetwork"},
		{"hostPID", "hostPID"},
		{"hostIPC", "hostIPC"},
	} {
		if b, ok := boolValue(mapValue(podSpec, field.key)); ok && b {
			add("K002", "high", prefix+"."+field.path, "", fmt.Sprintf("pod enables %s", field.key))
		}
	}

	// K003: hostPath volumes.
	if volumes := seqItems(mapValue(podSpec, "volumes")); volumes != nil {
		for i, vol := range volumes {
			if mapValue(vol, "hostPath") != nil {
				add("K003", "high", fmt.Sprintf("%s.volumes[%d].hostPath", prefix, i), "", "pod uses hostPath volume")
			}
		}
	}

	checkContainerList(seqItems(mapValue(podSpec, "containers")), "containers", prefix, kind, name, docIndex, disabled, podSecCtx, &findings)
	checkContainerList(seqItems(mapValue(podSpec, "initContainers")), "initContainers", prefix, kind, name, docIndex, disabled, podSecCtx, &findings)

	// K007: a pod-level seccomp profile is evaluated once, not once per
	// container, so a single pod-level defect produces a single finding.
	if podSeccompType := mapValue(mapValue(podSecCtx, "seccompProfile"), "type"); podSeccompType != nil {
		if t := scalarString(podSeccompType); t != "RuntimeDefault" && t != "Localhost" {
			add("K007", "medium", prefix+".securityContext.seccompProfile.type", "", "pod seccompProfile.type must be RuntimeDefault or Localhost")
		}
	}

	return findings
}

// checkContainerList evaluates all rules that are scoped to a list of
// containers (regular or init containers).
func checkContainerList(items []*yaml.Node, listName, prefix, kind, name string, docIndex int, disabled map[string]bool, podSecCtx *yaml.Node, findings *[]Finding) {
	if items == nil {
		return
	}

	add := func(rule, severity, path, container, msg string) {
		if disabled[rule] {
			return
		}
		*findings = append(*findings, Finding{
			Rule:      rule,
			Severity:  severity,
			Kind:      kind,
			Name:      name,
			Container: container,
			Path:      path,
			Message:   msg,
			Document:  docIndex,
		})
	}

	for i, item := range items {
		if item.Kind != yaml.MappingNode {
			continue
		}
		containerName := scalarString(mapValue(item, "name"))
		containerPrefix := fmt.Sprintf("%s.%s[%d]", prefix, listName, i)
		secCtx := mapValue(item, "securityContext")

		// K001: privileged containers.
		if b, ok := boolValue(mapValue(secCtx, "privileged")); ok && b {
			add("K001", "high", containerPrefix+".securityContext.privileged", containerName, fmt.Sprintf("container %s is privileged", containerName))
		}

		// K004: allowPrivilegeEscalation must be explicitly false.
		allowEscNode := mapValue(secCtx, "allowPrivilegeEscalation")
		if allowEscNode == nil {
			add("K004", "medium", containerPrefix+".securityContext.allowPrivilegeEscalation", containerName, fmt.Sprintf("container %s should set allowPrivilegeEscalation to false", containerName))
		} else if b, ok := boolValue(allowEscNode); !ok || b {
			add("K004", "medium", containerPrefix+".securityContext.allowPrivilegeEscalation", containerName, fmt.Sprintf("container %s should set allowPrivilegeEscalation to false", containerName))
		}

		// K005: running as non-root.
		runAsNonRootEffective := false
		containerRunAsNonRootNode := mapValue(secCtx, "runAsNonRoot")
		if b, ok := boolValue(containerRunAsNonRootNode); ok {
			runAsNonRootEffective = b
		} else {
			podRunAsNonRootNode := mapValue(podSecCtx, "runAsNonRoot")
			if b, ok := boolValue(podRunAsNonRootNode); ok {
				runAsNonRootEffective = b
			}
		}
		if !runAsNonRootEffective {
			add("K005", "medium", containerPrefix+".securityContext.runAsNonRoot", containerName, fmt.Sprintf("container %s must run as non-root", containerName))
		}

		// K005 (alternate): runAsUser 0.
		if runAsUserNode := mapValue(secCtx, "runAsUser"); runAsUserNode != nil {
			if v, ok := intValue(runAsUserNode); ok && v == 0 {
				add("K005", "medium", containerPrefix+".securityContext.runAsUser", containerName, fmt.Sprintf("container %s runs as root (runAsUser 0)", containerName))
			}
		}

		// K006: capabilities. A missing capabilities block also fails to drop
		// ALL, so it is reported like one without a drop list.
		capsNode := mapValue(secCtx, "capabilities")
		dropAll := false
		if capsNode != nil {
			if dropNode := mapValue(capsNode, "drop"); dropNode != nil {
				for _, d := range seqItems(dropNode) {
					if scalarString(d) == "ALL" {
						dropAll = true
						break
					}
				}
			}
		}
		if !dropAll {
			add("K006", "medium", containerPrefix+".securityContext.capabilities", containerName, fmt.Sprintf("container %s does not drop ALL capabilities", containerName))
		}
		if capsNode != nil {
			if addNode := mapValue(capsNode, "add"); addNode != nil {
				for _, a := range seqItems(addNode) {
					cap := scalarString(a)
					if cap != "NET_BIND_SERVICE" {
						add("K006", "medium", containerPrefix+".securityContext.capabilities", containerName, fmt.Sprintf("container %s adds capability %s", containerName, cap))
					}
				}
			}
		}

		// K007: seccomp profile. The container-level value wins; a missing
		// container value falls back to the pod-level value, which is checked
		// once per workload in checkWorkload.
		containerSeccompTypeNode := mapValue(mapValue(secCtx, "seccompProfile"), "type")
		if containerSeccompTypeNode != nil {
			if t := scalarString(containerSeccompTypeNode); t != "RuntimeDefault" && t != "Localhost" {
				add("K007", "medium", containerPrefix+".securityContext.seccompProfile.type", containerName, fmt.Sprintf("container %s must set seccompProfile.type to RuntimeDefault or Localhost", containerName))
			}
		} else if mapValue(mapValue(podSecCtx, "seccompProfile"), "type") == nil {
			add("K007", "medium", containerPrefix+".securityContext.seccompProfile.type", containerName, fmt.Sprintf("container %s must set seccompProfile.type to RuntimeDefault or Localhost", containerName))
		}

		// K008: image tag/digest hygiene.
		image := scalarString(mapValue(item, "image"))
		if image != "" {
			lastSlash := strings.LastIndex(image, "/")
			colonRel := -1
			if lastSlash >= 0 {
				colonRel = strings.Index(image[lastSlash+1:], ":")
			} else {
				colonRel = strings.Index(image, ":")
			}
			violation := false
			if colonRel == -1 {
				violation = true
			} else {
				tagStart := lastSlash + 1 + colonRel + 1
				if tagStart >= len(image) || image[tagStart:] == "latest" {
					violation = true
				}
			}
			if violation {
				add("K008", "low", containerPrefix+".image", containerName, fmt.Sprintf("container %s image should be pinned to a specific tag or digest", containerName))
			}
		}

		// K009: memory limit.
		res := mapValue(item, "resources")
		limits := mapValue(res, "limits")
		if mapValue(limits, "memory") == nil {
			add("K009", "low", containerPrefix+".resources.limits.memory", containerName, fmt.Sprintf("container %s should set resources.limits.memory", containerName))
		}

		// K010: host ports.
		if ports := seqItems(mapValue(item, "ports")); ports != nil {
			for j, port := range ports {
				if hpNode := mapValue(port, "hostPort"); hpNode != nil {
					if v, ok := intValue(hpNode); ok && v != 0 {
						add("K010", "medium", fmt.Sprintf("%s.ports[%d].hostPort", containerPrefix, j), containerName, fmt.Sprintf("container %s exposes host port", containerName))
					}
				}
			}
		}
	}
}
