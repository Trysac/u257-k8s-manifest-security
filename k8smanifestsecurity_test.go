package k8smanifestsecurity_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Trysac/u257-k8s-manifest-security"
)

func scanString(t *testing.T, input string, opts k8smanifestsecurity.Options) ([]k8smanifestsecurity.Finding, error) {
	t.Helper()
	return k8smanifestsecurity.Scan(strings.NewReader(input), opts)
}

func rulesOfFindings(findings []k8smanifestsecurity.Finding) []string {
	var rules []string
	for _, f := range findings {
		rules = append(rules, f.Rule)
	}
	return rules
}

func TestScanPrivilegedPod(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      privileged: true
`
	findings, err := scanString(t, input, k8smanifestsecurity.Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	got := rulesOfFindings(findings)
	// Findings are sorted by document, path and rule, so compare the rule
	// codes as a set: exactly these six rules must be reported.
	sort.Strings(got)
	want := []string{"K001", "K004", "K005", "K006", "K007", "K009"}
	if len(got) != len(want) {
		t.Fatalf("Scan() returned %d findings %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rules[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	// Check K001 details.
	var k001 *k8smanifestsecurity.Finding
	for i := range findings {
		if findings[i].Rule == "K001" {
			k001 = &findings[i]
			break
		}
	}
	if k001 == nil {
		t.Fatal("K001 not found")
	}
	if k001.Severity != "high" || k001.Kind != "Pod" || k001.Name != "web" || k001.Container != "app" || k001.Path != "spec.containers[0].securityContext.privileged" || k001.Document != 0 {
		t.Fatalf("K001 finding = %+v", *k001)
	}
}

func TestScanSecureDeployment(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: registry.example.com:5000/api:1.4.2
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        resources:
          limits:
            memory: "256Mi"
`
	findings, err := scanString(t, input, k8smanifestsecurity.Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Scan() = %v, want no findings", findings)
	}
}

func TestK008ImageRules(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  bool
	}{
		{"no tag", "nginx", true},
		{"latest tag", "nginx:latest", true},
		{"registry no tag", "registry.example.com:5000/app", true},
		{"specific tag", "registry.example.com:5000/app:1.2", false},
		{"digest", "nginx@sha256:" + strings.Repeat("a", 64), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\nspec:\n  containers:\n  - name: app\n    image: " + tt.image + "\n    securityContext:\n      allowPrivilegeEscalation: false\n      runAsNonRoot: true\n      capabilities:\n        drop: [\"ALL\"]\n      seccompProfile:\n        type: RuntimeDefault\n    resources:\n      limits:\n        memory: \"128Mi\"\n"
			findings, err := scanString(t, input, k8smanifestsecurity.Options{})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			hasK008 := false
			for _, f := range findings {
				if f.Rule == "K008" {
					hasK008 = true
					if f.Path != "spec.containers[0].image" {
						t.Fatalf("K008 path = %q, want spec.containers[0].image", f.Path)
					}
				}
			}
			if hasK008 != tt.want {
				t.Fatalf("K008 presence = %v, want %v (findings=%v)", hasK008, tt.want, findings)
			}
		})
	}
}

func TestCapabilities(t *testing.T) {
	t.Run("NET_ADMIN adds capability", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        add: ["NET_ADMIN"]
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
`
		findings, err := scanString(t, input, k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		var k006 *k8smanifestsecurity.Finding
		for i := range findings {
			if findings[i].Rule == "K006" {
				k006 = &findings[i]
				break
			}
		}
		if k006 == nil {
			t.Fatal("K006 not found")
		}
		if want := "container app adds capability NET_ADMIN"; k006.Message != want {
			t.Fatalf("K006.Message = %q, want %q", k006.Message, want)
		}
	})

	t.Run("NET_BIND_SERVICE with drop ALL no K006", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        add: ["NET_BIND_SERVICE"]
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
`
		findings, err := scanString(t, input, k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		for _, f := range findings {
			if f.Rule == "K006" {
				t.Fatalf("unexpected K006: %+v", f)
			}
		}
	})
}

func TestHostNamespacesAndHostPathAndCronJobAndPort(t *testing.T) {
	deployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
      - name: vol
        hostPath:
          path: /data
      containers:
      - name: app
        image: nginx:1.27
        ports:
        - containerPort: 8080
          hostPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
        resources:
          limits:
            memory: "128Mi"
`
	findings, err := scanString(t, deployment, k8smanifestsecurity.Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	var k002, k003, k010 bool
	for _, f := range findings {
		switch f.Rule {
		case "K002":
			k002 = true
			if f.Path != "spec.template.spec.hostNetwork" {
				t.Fatalf("K002 path = %q", f.Path)
			}
		case "K003":
			k003 = true
			if f.Path != "spec.template.spec.volumes[0].hostPath" {
				t.Fatalf("K003 path = %q", f.Path)
			}
		case "K010":
			k010 = true
			if f.Path != "spec.template.spec.containers[0].ports[0].hostPort" {
				t.Fatalf("K010 path = %q", f.Path)
			}
		}
	}
	if !k002 || !k003 || !k010 {
		t.Fatalf("expected K002/K003/K010, got %v", rulesOfFindings(findings))
	}

	cronJob := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: test
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: app
            image: nginx:1.27
            securityContext:
              privileged: true
`
	findings, err = scanString(t, cronJob, k8smanifestsecurity.Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, f := range findings {
		if f.Rule == "K001" && !strings.HasPrefix(f.Path, "spec.jobTemplate.spec.template.spec.containers[0]") {
			t.Fatalf("K001 path = %q, want prefix spec.jobTemplate.spec.template.spec.containers[0]", f.Path)
		}
	}
}

func TestMultipleDocuments(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
---
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`
	findings, err := scanString(t, input, k8smanifestsecurity.Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, f := range findings {
		if f.Rule == "K001" && f.Document != 1 {
			t.Fatalf("K001 Document = %d, want 1", f.Document)
		}
	}
}

func TestErrors(t *testing.T) {
	t.Run("input too large", func(t *testing.T) {
		big := strings.Repeat("a", 4_194_305)
		_, err := scanString(t, big, k8smanifestsecurity.Options{})
		if !errors.Is(err, k8smanifestsecurity.ErrInputTooLarge) {
			t.Fatalf("error = %v, want ErrInputTooLarge", err)
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		_, err := scanString(t, "not: [valid", k8smanifestsecurity.Options{})
		if !errors.Is(err, k8smanifestsecurity.ErrInvalidYAML) {
			t.Fatalf("error = %v, want ErrInvalidYAML", err)
		}
	})

	t.Run("alias nodes", func(t *testing.T) {
		input := `a: &x [1,2]
b: *x
`
		_, err := scanString(t, input, k8smanifestsecurity.Options{})
		if !errors.Is(err, k8smanifestsecurity.ErrInvalidYAML) {
			t.Fatalf("error = %v, want ErrInvalidYAML", err)
		}
	})

	t.Run("deep nesting", func(t *testing.T) {
		var sb strings.Builder
		for i := 0; i < 70; i++ {
			sb.WriteString(strings.Repeat(" ", i))
			sb.WriteString("a:\n")
		}
		sb.WriteString(strings.Repeat(" ", 70))
		sb.WriteString("b: c\n")
		_, err := scanString(t, sb.String(), k8smanifestsecurity.Options{})
		if !errors.Is(err, k8smanifestsecurity.ErrInvalidYAML) {
			t.Fatalf("error = %v, want ErrInvalidYAML", err)
		}
	})

	t.Run("flow nesting rejects before decode", func(t *testing.T) {
		_, err := scanString(t, strings.Repeat("[", 4<<20), k8smanifestsecurity.Options{})
		if !errors.Is(err, k8smanifestsecurity.ErrInvalidYAML) {
			t.Fatalf("error = %v, want ErrInvalidYAML", err)
		}
	})

	t.Run("too many documents", func(t *testing.T) {
		var sb strings.Builder
		for i := 0; i < 1001; i++ {
			sb.WriteString("---\nkey: value\n")
		}
		_, err := scanString(t, sb.String(), k8smanifestsecurity.Options{MaxBytes: 10_000_000})
		if !errors.Is(err, k8smanifestsecurity.ErrTooManyDocuments) {
			t.Fatalf("error = %v, want ErrTooManyDocuments", err)
		}
	})
}

func TestQuotedTrueNotBoolean(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      privileged: "true"
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
`
	findings, err := scanString(t, input, k8smanifestsecurity.Options{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, f := range findings {
		if f.Rule == "K001" {
			t.Fatalf("unexpected K001 for quoted true: %+v", f)
		}
	}
}

func TestDisabledRules(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
`
	findings, err := scanString(t, input, k8smanifestsecurity.Options{Disabled: []string{"K009", "K008"}})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, f := range findings {
		if f.Rule == "K009" || f.Rule == "K008" {
			t.Fatalf("disabled rule found: %+v", f)
		}
	}
}

func TestRunCLI(t *testing.T) {
	t.Run("text format with findings returns 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmp := filepath.Join(t.TempDir(), "pod.yaml")
		content := `apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
  - name: app
    image: nginx:latest
`
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rc := k8smanifestsecurity.Run([]string{"--format", "text", tmp}, &stdout, &stderr)
		if rc != 1 {
			t.Fatalf("Run() = %d, want 1; stderr=%s", rc, stderr.String())
		}
		if !strings.Contains(stdout.String(), "K008") {
			t.Fatalf("stdout should contain K008, got %q", stdout.String())
		}
	})

	t.Run("json format with no findings returns 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmp := filepath.Join(t.TempDir(), "pod.yaml")
		content := `apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
`
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rc := k8smanifestsecurity.Run([]string{"--format", "json", tmp}, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("Run() = %d, want 0; stderr=%s", rc, stderr.String())
		}
		var arr []k8smanifestsecurity.Finding
		if err := json.Unmarshal(stdout.Bytes(), &arr); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if len(arr) != 0 {
			t.Fatalf("json array = %v, want empty", arr)
		}
	})

	t.Run("json format with findings uses documented keys and returns 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmp := filepath.Join(t.TempDir(), "pod.yaml")
		content := `apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
`
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rc := k8smanifestsecurity.Run([]string{"--format", "json", tmp}, &stdout, &stderr)
		if rc != 1 {
			t.Fatalf("Run() = %d, want 1; stderr=%s", rc, stderr.String())
		}
		var arr []map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &arr); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if len(arr) == 0 {
			t.Fatal("json array is empty, want findings")
		}
		wantKeys := []string{"rule", "severity", "kind", "name", "container", "path", "message", "document"}
		for _, elem := range arr {
			if len(elem) != len(wantKeys) {
				t.Fatalf("element has %d keys, want %d: %v", len(elem), len(wantKeys), elem)
			}
			for _, key := range wantKeys {
				if _, ok := elem[key]; !ok {
					t.Fatalf("missing key %q in %v", key, elem)
				}
			}
		}
	})

	t.Run("invalid yaml returns 2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmp := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(tmp, []byte("not: [valid"), 0o644); err != nil {
			t.Fatal(err)
		}
		rc := k8smanifestsecurity.Run([]string{tmp}, &stdout, &stderr)
		if rc != 2 {
			t.Fatalf("Run() = %d, want 2; stderr=%s", rc, stderr.String())
		}
		if stderr.Len() == 0 {
			t.Fatal("stderr should explain the error")
		}
	})

	t.Run("stdin dash reads stdin", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		content := `apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
`
		if _, err := w.WriteString(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		oldStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = oldStdin }()
		defer r.Close()

		var stdout, stderr bytes.Buffer
		rc := k8smanifestsecurity.Run([]string{"-"}, &stdout, &stderr)
		if rc != 1 {
			t.Fatalf("Run() = %d, want 1; stderr=%s", rc, stderr.String())
		}
		if !strings.Contains(stdout.String(), "K001") {
			t.Fatalf("stdout should contain K001, got %q", stdout.String())
		}
	})

	t.Run("missing file returns 2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		rc := k8smanifestsecurity.Run([]string{"nonexistent.yaml"}, &stdout, &stderr)
		if rc != 2 {
			t.Fatalf("Run() = %d, want 2; stderr=%s", rc, stderr.String())
		}
	})

	t.Run("disabled flag removes K009", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmp := filepath.Join(t.TempDir(), "pod.yaml")
		content := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
`
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rc := k8smanifestsecurity.Run([]string{"--disable", "K009", tmp}, &stdout, &stderr)
		if rc != 1 {
			t.Fatalf("Run() = %d, want 1; stderr=%s", rc, stderr.String())
		}
		if strings.Contains(stdout.String(), "K009") {
			t.Fatalf("K009 should be disabled, got stdout %q", stdout.String())
		}
	})
}

func TestSpecEdgeCases(t *testing.T) {
	t.Run("pod runAsNonRoot overridden to false in one container", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      runAsNonRoot: false
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
  - name: sidecar
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
`
		findings, err := scanString(t, input, k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		var k005 []k8smanifestsecurity.Finding
		for _, f := range findings {
			if f.Rule == "K005" {
				k005 = append(k005, f)
			}
		}
		if len(k005) != 1 {
			t.Fatalf("K005 findings = %v, want exactly one", k005)
		}
		if want := "spec.containers[0].securityContext.runAsNonRoot"; k005[0].Path != want {
			t.Fatalf("K005 path = %q, want %q", k005[0].Path, want)
		}
		if k005[0].Container != "app" {
			t.Fatalf("K005 container = %q, want app", k005[0].Container)
		}
	})

	t.Run("initContainer violation uses initContainers path", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
  initContainers:
  - name: init
    image: busybox:1.36
    securityContext:
      privileged: true
`
		findings, err := scanString(t, input, k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		var k001 *k8smanifestsecurity.Finding
		for i := range findings {
			if findings[i].Rule == "K001" {
				k001 = &findings[i]
				break
			}
		}
		if k001 == nil {
			t.Fatal("K001 not found")
		}
		if want := "spec.initContainers[0].securityContext.privileged"; k001.Path != want {
			t.Fatalf("K001 path = %q, want %q", k001.Path, want)
		}
		if k001.Container != "init" {
			t.Fatalf("K001 container = %q, want init", k001.Container)
		}
	})

	t.Run("seccomp Unconfined is reported", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: Unconfined
    resources:
      limits:
        memory: "128Mi"
`
		findings, err := scanString(t, input, k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		found := false
		for _, f := range findings {
			if f.Rule == "K007" {
				found = true
				if want := "spec.containers[0].securityContext.seccompProfile.type"; f.Path != want {
					t.Fatalf("K007 path = %q, want %q", f.Path, want)
				}
			}
		}
		if !found {
			t.Fatal("K007 not found for Unconfined seccomp profile")
		}
	})

	t.Run("port without hostPort produces no K010", func(t *testing.T) {
		input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:1.27
    ports:
    - containerPort: 8080
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        memory: "128Mi"
`
		findings, err := scanString(t, input, k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		for _, f := range findings {
			if f.Rule == "K010" {
				t.Fatalf("unexpected K010: %+v", f)
			}
		}
	})

	t.Run("root list document is skipped", func(t *testing.T) {
		findings, err := scanString(t, "- a\n- b\n", k8smanifestsecurity.Options{})
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("Scan() = %v, want no findings", findings)
		}
	})
}

func ExampleScan() {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
  - name: app
    image: nginx:latest
`
	findings, err := k8smanifestsecurity.Scan(strings.NewReader(input), k8smanifestsecurity.Options{})
	if err != nil {
		panic(err)
	}
	for _, f := range findings {
		fmt.Printf("%s %s %s/%s %s: %s\n", f.Severity, f.Rule, f.Kind, f.Name, f.Path, f.Message)
	}
	// Output:
	// low K008 Pod/web spec.containers[0].image: container app image should be pinned to a specific tag or digest
	// low K009 Pod/web spec.containers[0].resources.limits.memory: container app should set resources.limits.memory
	// medium K004 Pod/web spec.containers[0].securityContext.allowPrivilegeEscalation: container app should set allowPrivilegeEscalation to false
	// medium K006 Pod/web spec.containers[0].securityContext.capabilities: container app does not drop ALL capabilities
	// medium K005 Pod/web spec.containers[0].securityContext.runAsNonRoot: container app must run as non-root
	// medium K007 Pod/web spec.containers[0].securityContext.seccompProfile.type: container app must set seccompProfile.type to RuntimeDefault or Localhost
}
