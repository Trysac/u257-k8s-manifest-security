// Package k8smanifestsecurity is a small, dependency-free Go library: Check Kubernetes workload manifests against Pod Security Standards baseline and restricted controls plus image and memory limit hygiene, with exact field paths and stable rule codes
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package k8smanifestsecurity
