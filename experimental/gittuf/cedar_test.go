// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"testing"

	"github.com/gittuf/gittuf/internal/dev"
	"github.com/gittuf/gittuf/internal/policy"
	policyopts "github.com/gittuf/gittuf/internal/policy/options/policy"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCedarPolicy = `forbid (
  principal,
  action == Gittuf::Action::"create",
  resource is Gittuf::GitRef
) when { resource.path like "refs/tags/*" };`

func TestAddCedarPolicy(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)

	t.Run("valid cedar policy", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddCedarPolicy(testCtx, rootSigner, "no-tags", []byte(testCedarPolicy), false)
		assert.Nil(t, err)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
		require.Nil(t, err)

		assert.Len(t, state.CedarPolicies, 1)
		assert.Equal(t, "no-tags", state.CedarPolicies[0].ID())
	})

	t.Run("invalid cedar source", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddCedarPolicy(testCtx, rootSigner, "bad-policy", []byte("not cedar"), false)
		assert.Error(t, err)
	})

	t.Run("empty policy name", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddCedarPolicy(testCtx, rootSigner, "", []byte(testCedarPolicy), false)
		assert.ErrorIs(t, err, ErrNoCedarPolicyName)
	})
}

func TestRemoveCedarPolicy(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)

	t.Run("add then remove", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddCedarPolicy(testCtx, rootSigner, "no-tags", []byte(testCedarPolicy), false)
		require.Nil(t, err)

		err = r.RemoveCedarPolicy(testCtx, rootSigner, "no-tags", false)
		assert.Nil(t, err)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
		require.Nil(t, err)

		assert.Empty(t, state.CedarPolicies)
	})

	t.Run("remove nonexistent", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.RemoveCedarPolicy(testCtx, rootSigner, "no-tags", false)
		assert.ErrorIs(t, err, tuf.ErrNoCedarPoliciesDefined)
	})
}

func TestAddAndRemoveGroup(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)

	t.Run("add group", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddGroup(testCtx, rootSigner, "release-team", []string{"alice"}, false)
		assert.Nil(t, err)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
		require.Nil(t, err)

		assert.Equal(t, []string{"alice"}, state.Groups["release-team"])
	})

	t.Run("remove group", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddGroup(testCtx, rootSigner, "release-team", []string{"alice"}, false)
		require.Nil(t, err)

		err = r.RemoveGroup(testCtx, rootSigner, "release-team", false)
		assert.Nil(t, err)

		state, err := policy.LoadCurrentState(testCtx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
		require.Nil(t, err)

		assert.Empty(t, state.Groups)
	})

	t.Run("remove nonexistent group", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.RemoveGroup(testCtx, rootSigner, "release-team", false)
		assert.ErrorIs(t, err, tuf.ErrNoGroupsDefined)
	})

	t.Run("remove missing group when another exists", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddGroup(testCtx, rootSigner, "release-team", []string{"alice"}, false)
		require.Nil(t, err)

		err = r.RemoveGroup(testCtx, rootSigner, "other-team", false)
		assert.ErrorIs(t, err, tuf.ErrGroupNotFound)
	})
}
