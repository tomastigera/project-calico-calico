// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package docindex

import (
	"strconv"
	"strings"
)

// DocIndex is used as a helper for processing document indexes of the form "1", "1.1" ...
// It is resilient in that the format does not require numerical values.
type DocIndex interface {
	Index() string
	LessThan(d DocIndex) bool
	Contains(d DocIndex) bool
}

// New creates a new DocIndex from the document index string.
func New(value string) DocIndex {
	d := &docIndex{
		index: value,
	}
	for part := range strings.SplitSeq(value, ".") {
		d.parts = append(d.parts, newIntOrString(part))
	}
	return d
}

// docIndex implements the DocIndex interface.
type docIndex struct {
	// The document index such as "1.1" or "1.1.1"
	index string

	// The individual parts of the section (e.g. []{1, 1, 1}
	parts []intOrString
}

// Index returns the original index string.
func (d *docIndex) Index() string {
	return d.index
}

// LessThan determines if this doc index is less than "other".
// -  1.1 is less than 1.1.1 (sections come before sub-sections)
// -  1 is less than abc (uint before non-uint).
func (d *docIndex) LessThan(other DocIndex) bool {
	odi := other.(*docIndex)
	for idx, p := range d.parts {
		if idx >= len(odi.parts) {
			// "s" has identical prefix but more parts the "compare", e.g. 1.1.1 vs 1.1 (treat 1.1.1 as higher).
			return false
		}
		if p.lessThan(odi.parts[idx]) {
			return true
		}
		if odi.parts[idx].lessThan(p) {
			return false
		}
	}
	return true
}

// Contains determines if this doc index contains the other index.
// For example, 2.1 contains 2.1.1 and 2.1.2
func (d *docIndex) Contains(other DocIndex) bool {
	odi := other.(*docIndex)
	if len(odi.parts) < len(d.parts) {
		return false
	}

	for idx, p := range d.parts {
		if p != odi.parts[idx] {
			return false
		}
	}
	return true
}

// newIntOrString creates a new intOrString value from the supplied string.
func newIntOrString(value string) intOrString {
	// Parse values up to the max of a uint16.
	if v, err := strconv.ParseUint(value, 10, 16); err == nil {
		return intOrString{
			num: int32(v),
		}
	}
	// Not a valid uint. Return as a string. Set numerical value to -1 as an indicator.
	return intOrString{
		num:    -1,
		string: value,
	}
}

// intOrString encapsulates a value as either an int or a string.
type intOrString struct {
	num    int32
	string string
}

// lessThan performs a comparison between two intOrString values.
// - If both are uints perform numerical comparison
// - If both are strings perform alphanumeric comparison
// - Otherwise a string > int.
func (i intOrString) lessThan(other intOrString) bool {
	if i.num == -1 {
		if other.num == -1 {
			// Both are string fields, do string comparison.
			return i.string < other.string
		}
		// This is a string field, other is an int. We define string > int, so return false.
		return false
	}
	if other.num == -1 {
		// This is an int field, other is a string. We define string > int, so return true.
		return true
	}
	// Both are int fields, do int comparison.
	return i.num < other.num
}

// SortableDocIndexes extends a slice of DocIndex to provide the sort interface.
type SortableDocIndexes []DocIndex

func (s SortableDocIndexes) Len() int      { return len(s) }
func (s SortableDocIndexes) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s SortableDocIndexes) Less(i, j int) bool {
	return s[i].LessThan(s[j])
}
