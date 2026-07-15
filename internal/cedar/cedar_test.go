// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package cedar

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const forbidTagsPolicy = `forbid (
  principal,
  action == Gittuf::Action::"create",
  resource is Gittuf::GitRef
) when { resource.path like "refs/tags/*" };`

func TestValidate(t *testing.T) {
	t.Parallel()

	assert.Nil(t, Validate("no-tags", []byte(forbidTagsPolicy)))

	err := Validate("bad", []byte("this is not cedar"))
	assert.NotNil(t, err)
}

func TestAddPolicies(t *testing.T) {
	t.Parallel()

	policySet := NewPolicySet()
	err := policySet.AddPolicies("no-tags", []byte(forbidTagsPolicy))
	assert.Nil(t, err)
	assert.NotNil(t, policySet.ps.Get("no-tags/policy0"))

	err = policySet.AddPolicies("no-tags", []byte(forbidTagsPolicy))
	assert.ErrorContains(t, err, "already added")

	err = policySet.AddPolicies("bad", []byte("this is not cedar"))
	assert.NotNil(t, err)
}
