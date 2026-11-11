package k8smanifestsecurity

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Run executes the k8s-manifest-security command-line interface. It returns
// 0 when there are no findings, 1 when there are findings, and 2 on any error
// (bad flags, unreadable input, invalid YAML, etc.).
func Run(args []string, stdout, stderr io.Writer) int {
	format := "text"
	var disabled []string
	var files []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "missing value for --format")
				return 2
			}
			format = args[i]
			if format != "text" && format != "json" {
				fmt.Fprintln(stderr, "invalid format: must be text or json")
				return 2
			}
		case arg == "--disable":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "missing value for --disable")
				return 2
			}
			for _, code := range strings.Split(args[i], ",") {
				if trimmed := strings.TrimSpace(code); trimmed != "" {
					disabled = append(disabled, trimmed)
				}
			}
		case arg == "-":
			files = append(files, arg)
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
			return 2
		default:
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(stderr, "no input files")
		return 2
	}

	opts := Options{Disabled: disabled}
	var all []Finding = make([]Finding, 0)

	for _, file := range files {
		var r io.Reader
		if file == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(file)
			if err != nil {
				fmt.Fprintf(stderr, "open %s: %v\n", file, err)
				return 2
			}
			defer f.Close()
			r = f
		}

		fs, err := Scan(r, opts)
		if err != nil {
			fmt.Fprintf(stderr, "scan %s: %v\n", file, err)
			return 2
		}
		all = append(all, fs...)
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Document != all[j].Document {
			return all[i].Document < all[j].Document
		}
		if all[i].Path != all[j].Path {
			return all[i].Path < all[j].Path
		}
		return all[i].Rule < all[j].Rule
	})

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(all); err != nil {
			fmt.Fprintf(stderr, "encode json: %v\n", err)
			return 2
		}
	} else {
		for _, f := range all {
			fmt.Fprintf(stdout, "%s %s %s/%s %s: %s\n", f.Severity, f.Rule, f.Kind, f.Name, f.Path, f.Message)
		}
	}

	if len(all) > 0 {
		return 1
	}
	return 0
}
