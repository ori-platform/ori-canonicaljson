// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The reasons a wire document is refused, as ori-specs gateway-api/v2's strict
// member rule names them, in its order of precedence: when several apply, the
// earliest wins, so every reader names the same reason whatever order its
// parser finds violations in. A refusal wraps exactly one of them.
var (
	// ErrInvalidUnicode is invalid UTF-8, or a lone or misordered surrogate
	// escape, in any name or value.
	ErrInvalidUnicode = errors.New("canonicaljson: invalid_unicode")
	// ErrMalformedJSON is a document that is not one JSON value, NaN and
	// Infinity included.
	ErrMalformedJSON = errors.New("canonicaljson: malformed_json")
	// ErrNestingTooDeep is nesting above MaxNestingDepth.
	ErrNestingTooDeep = errors.New("canonicaljson: nesting_too_deep")
	// ErrTrailingData is anything other than whitespace after the value.
	ErrTrailingData = errors.New("canonicaljson: trailing_data")
	// ErrDuplicateMember is two members of one object with identical names,
	// compared after unescaping, code point for code point.
	ErrDuplicateMember = errors.New("canonicaljson: duplicate_member")
	// ErrCaseVariantMember is two names in one object, or a name and a member
	// the caller's Shape defines for that object, that differ but are equal
	// under the closed fold.
	ErrCaseVariantMember = errors.New("canonicaljson: case_variant_member")
)

// Refusals that follow the strict member rule's reasons: the document obeys
// the rule, and is not the object the caller asked for.
var (
	// ErrNotAnObject is a top-level value that is not a JSON object.
	ErrNotAnObject = errors.New("canonicaljson: not_an_object")
	// ErrMissingMember is a member a Shape requires that is absent.
	ErrMissingMember = errors.New("canonicaljson: missing_member")
)

// MaxNestingDepth is the deepest nesting admitted, counting objects and
// arrays, with the top-level value at depth 1.
const MaxNestingDepth = 32

// Shape describes an object the caller expects. It never makes a document
// acceptable that the strict member rule refuses; it adds the refusals that
// need the contract's names.
type Shape struct {
	// Members are the member names the contract defines for the object. A
	// name that is not one of them but is equal to one under the closed fold
	// is refused as ErrCaseVariantMember. Other names are tolerated.
	Members []string
	// Required are the members that must be present, refused as
	// ErrMissingMember when absent. A required name is a defined one.
	Required []string
	// Objects gives the shape of a member whose value is an object. A member
	// whose value is not an object is left to the caller.
	Objects map[string]*Shape
}

// DecodeStrict checks raw under the strict member rule and shape, and returns
// the top-level object's members by exact name, each value the bytes it
// arrived as. A member holding an object can be decoded the same way with its
// shape. shape may be nil, which defines no members.
func DecodeStrict(raw []byte, shape *Shape) (map[string]json.RawMessage, error) {
	if err := check(raw, shape, memberRule); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedJSON, err)
	}
	return members, nil
}

// rule is the set of refusals a check applies.
type rule struct {
	// strict adds the refusals of gateway-api/v2's strict member rule that
	// not every contract makes: nesting_too_deep, case_variant_member and
	// not_an_object.
	strict bool
	// trackDepth is how deep names are tracked. A level past it is only
	// parsed: no refusal it could hold would change the outcome.
	trackDepth int
}

// maxDecoderDepth is the nesting encoding/json refuses beyond.
const maxDecoderDepth = 10000

var (
	// memberRule is gateway-api/v2's strict member rule, for runtime-gateway
	// payloads. Past MaxNestingDepth only malformed_json can outrank the
	// nesting refusal already recorded.
	memberRule = rule{strict: true, trackDepth: MaxNestingDepth}
	// canonicalRule is what every contract MarshalWire canonicalises for
	// already refuses: invalid Unicode, malformed JSON, trailing data and a
	// member named twice. Past maxDecoderDepth the decode MarshalWire makes
	// next refuses the document anyway.
	canonicalRule = rule{trackDepth: maxDecoderDepth}
)

// check applies r to raw, then the refusals that need shape, and returns the
// highest-ranked refusal present.
func check(raw []byte, shape *Shape, r rule) error {
	if err := ValidateWireUnicode(raw); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUnicode, err)
	}
	s := scanner{data: raw, rule: r}
	if err := s.scan(shape); err != nil {
		return err
	}
	for _, found := range []*refusal{s.tooDeep, s.trailing, s.duplicate, s.caseVariant, s.notObject, s.missing} {
		if found != nil {
			return found.err()
		}
	}
	return nil
}

// refusal is the first instance of one reason the scan found.
type refusal struct {
	reason error
	detail string
}

func (r *refusal) err() error {
	if r.detail == "" {
		return r.reason
	}
	return fmt.Errorf("%w: %s", r.reason, r.detail)
}

// frame is one open object or array.
type frame struct {
	object bool
	shape  *Shape
	// For an object: the names seen, exactly and folded, and the member
	// whose value is being read. For an array: the next element's index.
	names  map[string]struct{}
	folded map[string]string
	member string
	index  int
}

// deepObject and deepArray stand for every level past the tracked depth.
var (
	deepObject = &frame{object: true}
	deepArray  = &frame{}
)

// scanner walks a document without recursion, so no depth limit of its own
// can turn a deep document into a syntax error: nesting_too_deep must outrank
// nothing but invalid_unicode and malformed_json. It records only the
// refusals its rule applies.
type scanner struct {
	data  []byte
	pos   int
	stack []*frame
	rule  rule

	tooDeep, trailing, duplicate, caseVariant, notObject, missing *refusal
}

func (s *scanner) malformed(what string) error {
	return fmt.Errorf("%w: %s at byte %d", ErrMalformedJSON, what, s.pos)
}

// scan reads one value and any trailing bytes, recording the first instance
// of each refusal below malformed_json and returning malformed_json at once.
func (s *scanner) scan(root *Shape) error {
	s.skipSpace()
	if s.rule.strict && s.pos < len(s.data) && s.data[s.pos] != '{' {
		s.notObject = &refusal{reason: ErrNotAnObject}
	}
	pending := root
	for {
		// A value starts here.
		s.skipSpace()
		if s.pos >= len(s.data) {
			return s.malformed("unexpected end of input")
		}
		switch c := s.data[s.pos]; {
		case c == '{' || c == '[':
			s.pos++
			var f *frame
			switch {
			case len(s.stack) >= s.rule.trackDepth:
				// Past the tracked depth a level is only parsed: it shares
				// one frame and tracks no names, and a hostile depth
				// costs a pointer a level.
				f = deepArray
				if c == '{' {
					f = deepObject
				}
			case c == '{':
				f = &frame{object: true, shape: pending, names: map[string]struct{}{}, folded: map[string]string{}}
			default:
				f = &frame{}
			}
			// An array's elements have no shape.
			pending = nil
			s.stack = append(s.stack, f)
			if s.rule.strict && len(s.stack) > MaxNestingDepth && s.tooDeep == nil {
				s.tooDeep = &refusal{reason: ErrNestingTooDeep, detail: "at " + s.path()}
			}
			s.skipSpace()
			closer := byte(']')
			if f.object {
				closer = '}'
			}
			if s.pos < len(s.data) && s.data[s.pos] == closer {
				s.pos++
				if err := s.closeContainer(); err != nil {
					return err
				}
				break
			}
			if f.object {
				shape, err := s.member()
				if err != nil {
					return err
				}
				pending = shape
			}
			continue
		case c == '"':
			if err := s.skipString(); err != nil {
				return err
			}
		case c == 't':
			if err := s.literal("true"); err != nil {
				return err
			}
		case c == 'f':
			if err := s.literal("false"); err != nil {
				return err
			}
		case c == 'n':
			if err := s.literal("null"); err != nil {
				return err
			}
		case c == '-' || (c >= '0' && c <= '9'):
			if err := s.number(); err != nil {
				return err
			}
		default:
			return s.malformed("invalid value")
		}
		// A value ended here: continue its container, or finish.
		next, done, err := s.afterValue()
		if err != nil {
			return err
		}
		if done {
			s.skipSpace()
			if s.pos < len(s.data) {
				s.trailing = &refusal{reason: ErrTrailingData, detail: fmt.Sprintf("at byte %d", s.pos)}
			}
			return nil
		}
		pending = next
	}
}

// afterValue consumes separators and closers after a value. It returns the
// shape of the next member's value, or done when the top-level value ended.
func (s *scanner) afterValue() (next *Shape, done bool, err error) {
	for {
		if len(s.stack) == 0 {
			return nil, true, nil
		}
		top := s.stack[len(s.stack)-1]
		s.skipSpace()
		if s.pos >= len(s.data) {
			return nil, false, s.malformed("unexpected end of input")
		}
		switch c := s.data[s.pos]; {
		case c == ',':
			s.pos++
			if top.object {
				shape, err := s.member()
				return shape, false, err
			}
			top.index++
			return nil, false, nil
		case top.object && c == '}', !top.object && c == ']':
			s.pos++
			if err := s.closeContainer(); err != nil {
				return nil, false, err
			}
		default:
			return nil, false, s.malformed("expected a separator or a closer")
		}
	}
}

// closeContainer pops the innermost container, checking an object's required
// members.
func (s *scanner) closeContainer() error {
	top := s.stack[len(s.stack)-1]
	if top.object && top.shape != nil && s.missing == nil {
		for _, name := range top.shape.Required {
			if _, ok := top.names[name]; !ok {
				s.missing = &refusal{reason: ErrMissingMember, detail: fmt.Sprintf("member %s at %s", boundedQuote(name), s.path())}
				break
			}
		}
	}
	s.stack = s.stack[:len(s.stack)-1]
	return nil
}

// member reads a member name and its colon, records the name against the
// innermost object, and returns the shape of the member's value.
func (s *scanner) member() (*Shape, error) {
	s.skipSpace()
	if s.pos >= len(s.data) || s.data[s.pos] != '"' {
		return nil, s.malformed("expected a member name")
	}
	start := s.pos
	if err := s.skipString(); err != nil {
		return nil, err
	}
	top := s.stack[len(s.stack)-1]
	if top.names == nil {
		// A level past the bound: its names cannot change the refusal.
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return nil, s.malformed("expected a colon")
		}
		s.pos++
		return nil, nil
	}
	var name string
	if err := json.Unmarshal(s.data[start:s.pos], &name); err != nil {
		return nil, s.malformed("invalid member name")
	}
	s.skipSpace()
	if s.pos >= len(s.data) || s.data[s.pos] != ':' {
		return nil, s.malformed("expected a colon")
	}
	s.pos++
	top.member = name
	if _, seen := top.names[name]; seen {
		if s.duplicate == nil {
			s.duplicate = &refusal{reason: ErrDuplicateMember, detail: fmt.Sprintf("member %s at %s", boundedQuote(name), s.path())}
		}
	} else {
		top.names[name] = struct{}{}
	}
	key := fold(name)
	if other, seen := top.folded[key]; seen && other != name {
		s.noteCaseVariant(name, other)
	} else if !seen {
		top.folded[key] = name
	}
	if top.shape == nil {
		return nil, nil
	}
	for _, defined := range top.shape.Members {
		if defined != name && fold(defined) == key {
			s.noteCaseVariant(name, defined)
		}
	}
	return top.shape.Objects[name], nil
}

func (s *scanner) noteCaseVariant(name, other string) {
	if s.rule.strict && s.caseVariant == nil {
		s.caseVariant = &refusal{reason: ErrCaseVariantMember, detail: fmt.Sprintf(
			"member %s and %s at %s", boundedQuote(name), boundedQuote(other), s.path())}
	}
}

// skipString reads past a JSON string at the cursor. ValidateWireUnicode has
// already refused invalid UTF-8 and surrogates.
func (s *scanner) skipString() error {
	s.pos++
	for {
		if s.pos >= len(s.data) {
			return s.malformed("unterminated string")
		}
		c := s.data[s.pos]
		switch {
		case c == '"':
			s.pos++
			return nil
		case c < 0x20:
			return s.malformed("control character in a string")
		case c == '\\':
			s.pos++
			if s.pos >= len(s.data) {
				return s.malformed("unterminated escape")
			}
			switch s.data[s.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.pos++
			case 'u':
				if s.pos+5 > len(s.data) {
					return s.malformed("short unicode escape")
				}
				for _, h := range s.data[s.pos+1 : s.pos+5] {
					if !isHex(h) {
						return s.malformed("invalid unicode escape")
					}
				}
				s.pos += 5
			default:
				return s.malformed("invalid escape")
			}
		default:
			s.pos++
		}
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func (s *scanner) literal(word string) error {
	if !strings.HasPrefix(string(s.data[s.pos:min(len(s.data), s.pos+len(word))]), word) {
		return s.malformed("invalid literal")
	}
	s.pos += len(word)
	return nil
}

// number reads -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?.
func (s *scanner) number() error {
	if s.data[s.pos] == '-' {
		s.pos++
	}
	switch {
	case s.pos < len(s.data) && s.data[s.pos] == '0':
		s.pos++
	case s.pos < len(s.data) && s.data[s.pos] >= '1' && s.data[s.pos] <= '9':
		s.digits()
	default:
		return s.malformed("invalid number")
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if s.digits() == 0 {
			return s.malformed("invalid number")
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if s.digits() == 0 {
			return s.malformed("invalid number")
		}
	}
	return nil
}

func (s *scanner) digits() int {
	n := 0
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
		n++
	}
	return n
}

func (s *scanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// path is the JSON Pointer of the innermost open container.
func (s *scanner) path() string {
	var b strings.Builder
	for _, f := range s.stack[:max(len(s.stack)-1, 0)] {
		b.WriteByte('/')
		if f.object {
			b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(f.member))
		} else {
			b.WriteString(strconv.Itoa(f.index))
		}
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

// fold maps a name under the closed fold: ASCII letters fold to lower case,
// U+017F to 's' and U+212A to 'k', and every other code point is kept. It is
// deliberately not Unicode case folding, which depends on the Unicode version
// a toolchain ships: these are exactly the code points encoding/json matches
// to an ASCII struct field name.
func fold(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == '\u017f':
			return 's'
		case r == '\u212a':
			return 'k'
		}
		return r
	}, name)
}

const maxQuotedName = 64

// boundedQuote quotes a name for an error, cut at maxQuotedName bytes.
func boundedQuote(name string) string {
	if len(name) > maxQuotedName {
		return strconv.Quote(name[:maxQuotedName]) + "..."
	}
	return strconv.Quote(name)
}
