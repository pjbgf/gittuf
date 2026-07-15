// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"testing"

	"github.com/gittuf/gittuf/internal/dev"
	"github.com/gittuf/gittuf/internal/policy"
	policyopts "github.com/gittuf/gittuf/internal/policy/options/policy"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
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

func TestEvaluateCedarVetoesNoPolicy(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	// A completely fresh git repository has no RSL entries and therefore no
	// applied policy. EvaluateCedarVetoes must return (nil, nil).
	tmpDir := t.TempDir()
	repoR := gitinterface.CreateTestGitRepository(t, tmpDir, false)
	r := &Repository{r: repoR}

	violations, err := r.EvaluateCedarVetoes(testCtx, []ProposedRefUpdate{
		{RefName: "refs/tags/v1.0.0", Action: CedarActionCreate, PrincipalID: "SHA256:unknown"},
	})
	assert.Nil(t, err)
	assert.Empty(t, violations)
}

func TestEvaluateCedarVetoesInvalidAction(t *testing.T) {
	t.Parallel()

	// An action value with wrong casing ("Create" instead of "create") must be
	// rejected before any state is loaded, not silently pass through as a
	// non-matching action that bypasses forbids.
	tmpDir := t.TempDir()
	repoR := gitinterface.CreateTestGitRepository(t, tmpDir, false)
	r := &Repository{r: repoR}

	_, err := r.EvaluateCedarVetoes(testCtx, []ProposedRefUpdate{
		{RefName: "refs/tags/v1.0.0", Action: "Create", PrincipalID: "SHA256:unknown"},
	})
	assert.Error(t, err)
}

func TestEvaluateCedarVetoes(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)

	t.Run("single forbid policy vetoes matching update only", func(t *testing.T) {
		r := createTestRepositoryWithRoot(t, "")

		err := r.AddCedarPolicy(testCtx, rootSigner, "no-tags", []byte(testCedarPolicy), false)
		require.Nil(t, err)

		// Record RSL entry for the staging ref so Apply can reconcile it, then
		// promote staging → applied policy.
		require.Nil(t, r.StagePolicy(testCtx, "", true, false))
		require.Nil(t, policy.Apply(testCtx, r.r, false))

		violations, err := r.EvaluateCedarVetoes(testCtx, []ProposedRefUpdate{
			{RefName: "refs/tags/v1.0.0", Action: CedarActionCreate, PrincipalID: "SHA256:unknown"},
			{RefName: "refs/heads/main", Action: CedarActionUpdate, PrincipalID: "SHA256:unknown"},
		})
		assert.Nil(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, "refs/tags/v1.0.0", violations[0].RefName)
		assert.Equal(t, "create", violations[0].Action)
		assert.Equal(t, []string{"no-tags/policy0"}, violations[0].PolicyIDs)
	})

	t.Run("no cedar policies means no violations", func(t *testing.T) {
		// createTestRepositoryWithRoot already applies the policy, but it
		// carries no cedar policies.
		r := createTestRepositoryWithRoot(t, "")

		violations, err := r.EvaluateCedarVetoes(testCtx, []ProposedRefUpdate{
			{RefName: "refs/tags/v1.0.0", Action: CedarActionCreate, PrincipalID: "SHA256:unknown"},
		})
		assert.Nil(t, err)
		assert.Empty(t, violations)
	})
}

func TestEvaluateCedarVetoesGroupCarveOut(t *testing.T) {
	t.Setenv(dev.DevModeKey, "1")

	const groupCarveOutPolicy = `forbid (
  principal,
  action == Gittuf::Action::"create",
  resource is Gittuf::GitRef
) when { resource.path like "refs/tags/*" }
unless { principal in Gittuf::Group::"release-team" };`

	rootSigner := setupSSHKeysForSigning(t, rootKeyBytes, rootPubKeyBytes)
	r := createTestRepositoryWithRoot(t, "")

	err := r.AddGroup(testCtx, rootSigner, "release-team", []string{"SHA256:releaser"}, false)
	require.Nil(t, err)

	err = r.AddCedarPolicy(testCtx, rootSigner, "no-tags-except-release-team", []byte(groupCarveOutPolicy), false)
	require.Nil(t, err)

	// Record RSL entry for the staging ref so Apply can reconcile it, then
	// promote staging → applied policy.
	require.Nil(t, r.StagePolicy(testCtx, "", true, false))
	require.Nil(t, policy.Apply(testCtx, r.r, false))

	t.Run("group member is not vetoed", func(t *testing.T) {
		violations, err := r.EvaluateCedarVetoes(testCtx, []ProposedRefUpdate{
			{RefName: "refs/tags/v1.0.0", Action: CedarActionCreate, PrincipalID: "SHA256:releaser"},
		})
		assert.Nil(t, err)
		assert.Empty(t, violations)
	})

	t.Run("non-member is vetoed", func(t *testing.T) {
		violations, err := r.EvaluateCedarVetoes(testCtx, []ProposedRefUpdate{
			{RefName: "refs/tags/v1.0.0", Action: CedarActionCreate, PrincipalID: "SHA256:unknown"},
		})
		assert.Nil(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, "refs/tags/v1.0.0", violations[0].RefName)
		assert.Equal(t, []string{"no-tags-except-release-team/policy0"}, violations[0].PolicyIDs)
	})
}
