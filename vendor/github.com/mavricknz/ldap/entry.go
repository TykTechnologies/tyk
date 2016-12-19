// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Entry structures and functions
package ldap

import (
	"strings"
)

type Entry struct {
	DN         string
	Attributes []*EntryAttribute
}

type EntryAttribute struct {
	Name   string
	Values []string
}

func (req *Entry) RecordType() uint8 {
	return EntryRecord
}

func NewEntry(dn string) *Entry {
	entry := &Entry{DN: dn}
	entry.Attributes = make([]*EntryAttribute, 0)
	return entry
}

// AddAttributeValue - Add a single Attr value
// no check is done for duplicate values.
func (e *Entry) AddAttributeValue(attributeName, value string) {
	index := e.GetAttributeIndex(attributeName)
	if index == -1 {
		eAttr := EntryAttribute{Name: attributeName, Values: []string{value}}
		e.Attributes = append(e.Attributes, &eAttr)
	} else {
		e.Attributes[index].Values = append(e.Attributes[index].Values, value)
	}
}

// AddAttributeValues - Add via a name and slice of values
// no check is done for duplicate values.
func (e *Entry) AddAttributeValues(attributeName string, values []string) {
	index := e.GetAttributeIndex(attributeName)
	if index == -1 {
		eAttr := &EntryAttribute{Name: attributeName, Values: values}
		e.Attributes = append(e.Attributes, eAttr)
	} else {
		e.Attributes[index].Values = append(e.Attributes[index].Values, values...)
	}
}

func (e *Entry) GetAttributeValues(attributeName string) []string {
	attributeName = strings.ToLower(attributeName)
	for _, attr := range e.Attributes {
		if strings.ToLower(attr.Name) == attributeName {
			return attr.Values
		}
	}
	return []string{}
}

// GetAttributeValue - returning an empty string is a bad idea
// some directory servers will return empty attr values (Sunone).
// Just asking for trouble.
func (e *Entry) GetAttributeValue(attributeName string) string {
	values := e.GetAttributeValues(attributeName)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (e *Entry) GetAttributeIndex(Attribute string) int {
	Attribute = strings.ToLower(Attribute)
	for i, attr := range e.Attributes {
		if strings.ToLower(attr.Name) == Attribute {
			return i
		}
	}
	return -1
}

// TODO: Proper LDIF writer, currently just for testing...
func (e *Entry) String() string {
	ldif := "dn: " + e.DN + "\n"
	for _, attr := range e.Attributes {
		for _, val := range attr.Values {
			ldif += attr.Name + ": " + val + "\n"
		}
	}
	return ldif
}
