package k8smanifestsecurity

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"go.yaml.in/yaml/v3"
)

const (
	defaultMaxBytes     = 4_194_304
	defaultMaxDocuments = 1000
	maxYAMLDepth        = 64
)

// Scan reads YAML from r, parses it as a stream of Kubernetes documents and
// returns all findings sorted by document index, path and rule. It enforces
// the limits from opts, rejecting oversized input, invalid YAML, alias nodes,
// excessive nesting and too many documents.
func Scan(r io.Reader, opts Options) ([]Finding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	maxDocuments := opts.MaxDocuments
	if maxDocuments <= 0 {
		maxDocuments = defaultMaxDocuments
	}

	// Read at most one byte beyond the limit so an unbounded reader cannot
	// exhaust memory before the size check runs.
	data, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("%w: %d bytes exceed limit %d", ErrInputTooLarge, len(data), maxBytes)
	}
	// Validate the raw bytes before the recursive YAML decoder runs, so an
	// oversized nesting depth can never exhaust the goroutine stack.
	if err := validateRaw(data); err != nil {
		return nil, fmt.Errorf("%w: document 0: %v", ErrInvalidYAML, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	disabledSet := make(map[string]bool, len(opts.Disabled))
	for _, code := range opts.Disabled {
		disabledSet[code] = true
	}

	var findings []Finding
	docIndex := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: document %d: %v", ErrInvalidYAML, docIndex, err)
		}
		if err := validateNode(&doc, 1); err != nil {
			return nil, fmt.Errorf("%w: document %d: %v", ErrInvalidYAML, docIndex, err)
		}

		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
			findings = append(findings, checkWorkload(doc.Content[0], docIndex, disabledSet)...)
		}
		docIndex++
	}

	if docIndex > maxDocuments {
		return nil, fmt.Errorf("%w: %d documents exceed limit %d", ErrTooManyDocuments, docIndex, maxDocuments)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Document != findings[j].Document {
			return findings[i].Document < findings[j].Document
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings, nil
}

// validateRaw estimates the maximum structural nesting depth of the raw YAML
// bytes without parsing them, using flow indicators and block indentation.
// This runs before decoding so a pathological document cannot overflow the
// stack inside the recursive YAML parser.
func validateRaw(data []byte) error {
	if depth := maxFlowDepth(data); depth > maxYAMLDepth {
		return fmt.Errorf("nesting depth exceeds %d", maxYAMLDepth)
	}
	if depth := maxBlockDepth(data); depth > maxYAMLDepth {
		return fmt.Errorf("nesting depth exceeds %d", maxYAMLDepth)
	}
	return nil
}

// maxFlowDepth returns the deepest nesting of flow collections ([ { ) found in
// data, ignoring content inside quoted scalars and comments.
func maxFlowDepth(data []byte) int {
	depth, maxDepth := 0, 0
	var quote byte
	for i := 0; i < len(data); i++ {
		c := data[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case '[', '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return maxDepth
}

// maxBlockDepth returns the deepest block nesting implied by the indentation
// of the logical lines in data. It over-approximates in the presence of block
// scalars, which is acceptable for a hard safety limit.
func maxBlockDepth(data []byte) int {
	maxDepth := 0
	var indents []int
	lineStart := 0
	for lineStart <= len(data) {
		lineEnd := lineStart
		for lineEnd < len(data) && data[lineEnd] != '\n' {
			lineEnd++
		}
		line := data[lineStart:lineEnd]
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		trimmed := string(line[indent:])
		if trimmed != "" && trimmed != "---" && trimmed != "..." && trimmed[0] != '#' {
			for len(indents) > 0 && indent < indents[len(indents)-1] {
				indents = indents[:len(indents)-1]
			}
			if len(indents) == 0 || indent > indents[len(indents)-1] {
				indents = append(indents, indent)
			}
			if len(indents) > maxDepth {
				maxDepth = len(indents)
			}
		}
		lineStart = lineEnd + 1
	}
	return maxDepth
}

// validateNode recursively checks a decoded YAML node tree for alias nodes and
// excessive nesting. Only collection nodes increase the depth; scalar keys do
// not. The root mapping starts at depth 1.
func validateNode(n *yaml.Node, depth int) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("alias nodes are not allowed")
	}

	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := validateNode(c, 1); err != nil {
				return err
			}
		}
	case yaml.MappingNode, yaml.SequenceNode:
		if depth > maxYAMLDepth {
			return fmt.Errorf("nesting depth exceeds %d", maxYAMLDepth)
		}
		for _, c := range n.Content {
			childDepth := depth
			if c.Kind == yaml.MappingNode || c.Kind == yaml.SequenceNode {
				childDepth = depth + 1
			}
			if err := validateNode(c, childDepth); err != nil {
				return err
			}
		}
	}
	return nil
}
