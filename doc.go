// Package k8smanifestsecurity checks Kubernetes workload manifests against
// Pod Security Standards baseline and restricted controls plus image and
// memory limit hygiene. It reports each violation with a stable rule code,
// severity and the exact field path to fix.
package k8smanifestsecurity
