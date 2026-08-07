// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"fmt"
	"regexp"
	"strings"
)

// This file mirrors the RSL entry custom-field validation in pkg/rsl/rsl.go.
// Root metadata carries the same shape of signed, application-defined fields, so
// the two validations are kept behaviourally identical. If one changes, update
// the other. The RSL package is not imported here to avoid coupling root
// metadata to the RSL storage layer and to keep pkg/rsl importable on its own.

const (
	// CustomFieldPrefix identifies extension fields in root metadata. It matches
	// rsl.CustomFieldPrefix.
	CustomFieldPrefix = "custom."

	// maxCustomFieldKeyLength is the exclusive upper bound on a custom field
	// key's length, including CustomFieldPrefix. A key must be shorter than this.
	maxCustomFieldKeyLength = 250

	// maxCustomFieldValueLength is the exclusive upper bound on a custom field
	// value's length. A value must be shorter than this.
	maxCustomFieldValueLength = 500

	// maxCustomFieldCount bounds how many custom fields the metadata may carry.
	maxCustomFieldCount = 20
)

// customFieldDomainLabel matches a single lowercase DNS label. customFieldName
// matches a Kubernetes-style name segment: lowercase, starting and ending
// alphanumeric, with '.', '_', and '-' allowed in between.
var (
	customFieldDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	customFieldName        = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
)

// ValidateCustomFields checks that the fields are well formed. A key must begin
// with CustomFieldPrefix and follow the Kubernetes annotation convention: a
// lowercase DNS subdomain (the namespace an application controls), a '/', and a
// name of at most 63 lowercase characters starting and ending alphanumeric. The
// whole key must be shorter than maxCustomFieldKeyLength. A value may contain
// [A-Za-z0-9-+./,()_ ], must have no leading or trailing spaces, and be shorter
// than maxCustomFieldValueLength. The metadata carries at most
// maxCustomFieldCount fields.
func ValidateCustomFields(fields map[string]string) error {
	if len(fields) > maxCustomFieldCount {
		return fmt.Errorf("%w: %d fields exceed the maximum of %d", ErrInvalidCustomFields, len(fields), maxCustomFieldCount)
	}
	for key, value := range fields {
		if !validCustomFieldKey(key) {
			return fmt.Errorf("%w: invalid key %q", ErrInvalidCustomFields, key)
		}
		if !validCustomFieldValue(value) {
			return fmt.Errorf("%w: invalid value for %q", ErrInvalidCustomFields, key)
		}
	}
	return nil
}

func validCustomFieldKey(key string) bool {
	if !strings.HasPrefix(key, CustomFieldPrefix) || len(key) >= maxCustomFieldKeyLength {
		return false
	}
	domain, name, ok := strings.Cut(key[len(CustomFieldPrefix):], "/")
	if !ok {
		return false
	}
	return validCustomFieldDomain(domain) && validCustomFieldNameSegment(name)
}

// validCustomFieldDomain reports whether domain is a lowercase DNS subdomain, as
// Kubernetes requires for an annotation key's prefix.
func validCustomFieldDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 || !customFieldDomainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validCustomFieldNameSegment(name string) bool {
	return len(name) > 0 && len(name) <= 63 && customFieldName.MatchString(name)
}

func validCustomFieldValue(value string) bool {
	if len(value) >= maxCustomFieldValueLength {
		return false
	}
	// A leading or trailing space would not survive a round-trip through the
	// text encodings that reuse these fields, so reject it on write to match the
	// RSL entry rules.
	if value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-+./,()_ ", character) {
			continue
		}
		return false
	}
	return true
}
