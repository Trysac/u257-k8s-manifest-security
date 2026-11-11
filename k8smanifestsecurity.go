// Package k8smanifestsecurity checks Kubernetes workload manifests against
// Pod Security Standards baseline and restricted controls plus image and
// memory limit hygiene. It reports each violation with a stable rule code,
// severity and the exact field path to fix.
package k8smanifestsecurity

import "errors"

// ErrInputTooLarge is returned when the input exceeds Options.MaxBytes.
var ErrInputTooLarge = errors.New("k8smanifestsecurity: input exceeds maximum size")

// ErrInvalidYAML is returned when the input is not valid YAML or contains
// unsupported constructs such as alias nodes or excessive nesting.
var ErrInvalidYAML = errors.New("k8smanifestsecurity: invalid YAML")

// ErrTooManyDocuments is returned when the input contains more than
// Options.MaxDocuments YAML documents.
var ErrTooManyDocuments = errors.New("k8smanifestsecurity: too many documents")

// Options configures the scanner.
type Options struct {
	// MaxBytes is the maximum number of input bytes to read. A value <= 0
	// selects the default of 4,194,304 bytes (4 MiB).
	MaxBytes int

	// MaxDocuments is the maximum number of YAML documents in the input
	// stream. A value <= 0 selects the default of 1000 documents.
	MaxDocuments int

	// Disabled contains rule codes (for example "K009") that should not be
	// reported. Empty or unknown codes are ignored.
	Disabled []string
}

// Finding describes a single security issue discovered in a workload.
type Finding struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Path      string `json:"path"`
	Message   string `json:"message"`
	Document  int    `json:"document"`
}
