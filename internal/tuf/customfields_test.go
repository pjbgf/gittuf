// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCustomFields(t *testing.T) {
	t.Parallel()

	invalid := map[string]map[string]string{
		"missing namespace":    {"field": "value"},
		"no custom prefix":     {"entire.io/repository": "value"},
		"no name separator":    {"custom.entire.io": "value"},
		"empty name":           {"custom.entire.io/": "value"},
		"empty domain":         {"custom./field": "value"},
		"uppercase key":        {"custom.entire.io/Repository": "value"},
		"key with space":       {"custom.entire.io/repo id": "value"},
		"bad domain label":     {"custom.-bad.io/field": "value"},
		"name too long":        {"custom.entire.io/" + strings.Repeat("a", 64): "value"},
		"key too long":         {"custom." + strings.Repeat("a.", 125) + "com/field": "value"},
		"value with colon":     {"custom.entire.io/field": "a:b"},
		"multiline value":      {"custom.entire.io/field": "first\nsecond"},
		"value leading space":  {"custom.entire.io/field": " value"},
		"value trailing space": {"custom.entire.io/field": "value "},
		"value too long":       {"custom.entire.io/field": strings.Repeat("a", maxCustomFieldValueLength)},
	}

	for name, fields := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.ErrorIs(t, ValidateCustomFields(fields), ErrInvalidCustomFields)
		})
	}

	valid := map[string]map[string]string{
		"ulid repository":     {"custom.entire.io/repository": "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		"symbols":             {"custom.example.com/field": "v1.2.3-rc.1/build(42),ok"},
		"internal space":      {"custom.example.com/field": "hello world"},
		"underscore":          {"custom.example.com/field": "hello_world"},
		"single label domain": {"custom.example/field": "value"},
		"subdomains":          {"custom.a.b.example.com/x-y_z.1": "value"},
		"max name length":     {"custom.example.com/" + strings.Repeat("a", 63): "value"},
		"max value length":    {"custom.example.com/field": strings.Repeat("a", maxCustomFieldValueLength-1)},
	}

	for name, fields := range valid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, ValidateCustomFields(fields))
		})
	}
}

func TestValidateCustomFieldsRejectsTooManyFields(t *testing.T) {
	t.Parallel()

	fields := map[string]string{}
	for i := 0; i <= maxCustomFieldCount; i++ {
		fields[fmt.Sprintf("custom.example.com/field-%d", i)] = "v"
	}
	require.Len(t, fields, maxCustomFieldCount+1)
	assert.ErrorIs(t, ValidateCustomFields(fields), ErrInvalidCustomFields)
}
