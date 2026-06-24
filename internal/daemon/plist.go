package daemon

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// A minimal XML-plist reader for the one document the session probe consumes: ioreg's
// Root node. It decodes the value nesting cookiesync reads — dict, array, string,
// integer, real, true/false, data — into the Go any-tree (map[string]any, []any,
// string, int64, float64, bool, []byte) the same way Python's plistlib.loads does.
// Only the keys parseSession reads are load-bearing; the rest are decoded and
// discarded. cookiesync only reads plists here, so a full plistlib is overkill — the
// launchd plists synckit/service writes are templated, not parsed.

// decodePlist parses an Apple XML plist document and returns its root value. An empty
// document or a malformed one is an error rather than a silent nil.
func decodePlist(payload []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read plist: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "plist" {
			continue
		}
		return decodePlistValue(dec)
	}
}

// decodePlistValue reads the next value element under the cursor (the opening tag of a
// plist value) and returns the decoded Go value.
func decodePlistValue(dec *xml.Decoder) (any, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read plist value: %w", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			return decodeElement(dec, el)
		case xml.EndElement:
			// A closing tag with no value element inside (e.g. </plist>) yields nil.
			return nil, nil
		}
	}
}

func decodeElement(dec *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		return decodeDict(dec)
	case "array":
		return decodeArray(dec)
	case "true":
		return true, dec.Skip()
	case "false":
		return false, dec.Skip()
	case "string", "data":
		text, err := elementText(dec)
		if err != nil {
			return nil, err
		}
		if start.Name.Local == "data" {
			return []byte(text), nil
		}
		return text, nil
	case "integer":
		text, err := elementText(dec)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("plist integer %q: %w", text, err)
		}
		return n, nil
	case "real":
		text, err := elementText(dec)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("plist real %q: %w", text, err)
		}
		return f, nil
	default:
		// Unknown value type: skip its subtree and report it absent.
		return nil, dec.Skip()
	}
}

// decodeDict reads a <dict> body — alternating <key> elements and value elements —
// into a map, until its closing tag.
func decodeDict(dec *xml.Decoder) (map[string]any, error) {
	out := map[string]any{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read plist dict: %w", err)
		}
		switch el := tok.(type) {
		case xml.EndElement:
			return out, nil
		case xml.StartElement:
			if el.Name.Local != "key" {
				return nil, fmt.Errorf("plist dict: expected <key>, got <%s>", el.Name.Local)
			}
			key, err := elementText(dec)
			if err != nil {
				return nil, err
			}
			value, err := decodePlistValue(dec)
			if err != nil {
				return nil, err
			}
			out[key] = value
		}
	}
}

// decodeArray reads an <array> body into a slice, until its closing tag.
func decodeArray(dec *xml.Decoder) ([]any, error) {
	var out []any
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("read plist array: %w", err)
		}
		switch el := tok.(type) {
		case xml.EndElement:
			return out, nil
		case xml.StartElement:
			value, err := decodeElement(dec, el)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
	}
}

// elementText reads the character data of the element under the cursor and consumes
// its closing tag.
func elementText(dec *xml.Decoder) (string, error) {
	var b bytes.Buffer
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("read plist text: %w", err)
		}
		switch el := tok.(type) {
		case xml.CharData:
			b.Write(el)
		case xml.EndElement:
			return b.String(), nil
		}
	}
}
