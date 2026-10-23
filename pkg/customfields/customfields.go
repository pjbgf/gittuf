// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package customfields defines the format for signed, application-defined
// custom fields carried by RSL entries.
//
// Custom fields are advisory only and must be treated as untrusted input.
// gittuf treats them as opaque metadata and never consults them during
// verification, so their presence, absence, or contents cannot change a
// verification outcome.
//
// Consumers should make no assumptions about a value's
// contents unless they generated the data themselves, for example a forge
// reading back fields it stamped under its own namespace, and must not use
// custom fields to make security decisions.
package customfields

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	Prefix = "custom."

	// MaxKeyLength bounds a key, Prefix included. A key must be fewer than
	// MaxKeyLength characters, so a key of exactly this length is rejected.
	MaxKeyLength = 250

	// MaxValueLength bounds a value in bytes. A value must be fewer than
	// MaxValueLength bytes, so a value of exactly this length is rejected.
	// Git sets no limit on a ref name, so this matches Linux's PATH_MAX,
	// which bounds the path of a loose ref.
	MaxValueLength = 4096

	// MaxCount is the largest number of fields a field set may carry. Unlike
	// the length limits, it is inclusive: exactly MaxCount fields are valid.
	MaxCount = 20

	// ValuePunctuation is the ASCII punctuation a value may carry alongside
	// ASCII letters and digits. It covers common value shapes: emails and
	// handles (@), timestamps and URLs (:), base64 (=), and query strings (?,
	// &, %, #, ~), as well as internal spaces. It also holds every printable
	// ASCII character Git allows in a branch name. It is exported so an
	// application that maps its own input into a value, such as a forge
	// sanitizing a user handle, can do so against this alphabet instead of
	// restating it.
	ValuePunctuation = "-+./,()_ @:=%#?&~!\"$';<>]`{|}"
)

var (
	ErrInvalid = errors.New("invalid custom fields")

	// domainLabel matches a single lowercase DNS label.
	domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

	// nameSegment matches a Kubernetes-style name segment: lowercase, starting
	// and ending alphanumeric, with '.', '_', and '-' allowed in between.
	nameSegment = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
)

// validValueRune reports whether r may appear in a value. Git accepts any
// non-ASCII byte in a ref name, but non-graphic runes such as bidirectional
// overrides and zero-width joiners could disguise a value when it is rendered,
// so only graphic ones are allowed.
func validValueRune(r rune) bool {
	if r < utf8.RuneSelf {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || strings.ContainsRune(ValuePunctuation, r)
	}
	return unicode.IsGraphic(r)
}

// Validate checks that the fields are well formed. A field set
// carries at most MaxCount fields. Every entry is checked with ValidateField.
func Validate(fields map[string]string) error {
	if len(fields) > MaxCount {
		return fmt.Errorf("%w: %d fields exceed the maximum of %d", ErrInvalid, len(fields), MaxCount)
	}
	for key, value := range fields {
		if err := ValidateField(key, value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateField checks that a single field is well formed, returning an error
// wrapping ErrInvalid otherwise. It is the one per-field check shared by
// writers and readers of custom fields.
//
// A key is the Prefix, a lowercase DNS subdomain, a '/', and a name of at most
// 63 characters that starts and ends with a lowercase letter or digit and may
// carry '.', '_', and '-' in between. The whole key, Prefix included, must be
// fewer than MaxKeyLength characters.
//
// A value is valid UTF-8 of fewer than MaxValueLength bytes, has no leading or
// trailing ASCII space, and has every rune an ASCII letter, digit, one of the
// characters in ValuePunctuation, or a graphic non-ASCII rune
// (unicode.IsGraphic). A non-ASCII space may lead or trail a value. Any branch
// name Git accepts fits this alphabet, unless it carries invalid UTF-8 or a
// non-graphic non-ASCII rune, such as a control, format, private-use, or
// unassigned character. This is a check of a value's shape, so the empty
// string passes. Emptiness means the field is absent, which writers handle by
// dropping the field.
func ValidateField(key, value string) error {
	if !validKey(key) {
		return fmt.Errorf("%w: invalid key %q", ErrInvalid, key)
	}
	if !validValue(value) {
		return fmt.Errorf("%w: invalid value for %q", ErrInvalid, key)
	}
	return nil
}

// validKey reports whether key is a well-formed field key. See ValidateField
// for the grammar.
func validKey(key string) bool {
	if !strings.HasPrefix(key, Prefix) || len(key) >= MaxKeyLength {
		return false
	}
	domain, name, ok := strings.Cut(key[len(Prefix):], "/")
	if !ok {
		return false
	}
	return validDomain(domain) && validNameSegment(name)
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) > 63 || !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validNameSegment(name string) bool {
	return len(name) > 0 && len(name) <= 63 && nameSegment.MatchString(name)
}

// validValue reports whether value is a well-formed field value. See
// ValidateField for the alphabet. The empty string passes.
func validValue(value string) bool {
	if len(value) >= MaxValueLength || !utf8.ValidString(value) {
		return false
	}
	// The RSL entry parser trims ASCII whitespace from each value, so a
	// leading or trailing space would not round-trip and would desync from
	// the signed bytes. Space is the only ASCII whitespace in the alphabet.
	if strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
		return false
	}
	for _, character := range value {
		if !validValueRune(character) {
			return false
		}
	}
	return true
}
