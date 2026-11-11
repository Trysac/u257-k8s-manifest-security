package k8smanifestsecurity

import (
	"strconv"

	"go.yaml.in/yaml/v3"
)

// mapValue returns the value node for the given key in a mapping node, or nil
// if the node is not a mapping or the key is absent.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// seqItems returns the child nodes of a sequence node, or nil if the node is
// not a sequence.
func seqItems(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// scalarString returns the string value of a scalar node, or the empty string
// if the node is nil or not a scalar.
func scalarString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// boolValue interprets a YAML scalar as a boolean according to YAML 1.2 core
// schema: only unquoted "true" and "false" are recognised. The second return
// value reports whether the node was a valid boolean scalar.
func boolValue(n *yaml.Node) (bool, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false, false
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return false, false
	}
	switch n.Value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// intValue attempts to parse a YAML scalar as an integer. It returns the
// value and true if the node is a plain or tagged integer scalar.
func intValue(n *yaml.Node) (int64, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return 0, false
	}
	if n.Tag == "!!int" || n.Style == 0 {
		v, err := strconv.ParseInt(n.Value, 0, 64)
		if err == nil {
			return v, true
		}
	}
	return 0, false
}
