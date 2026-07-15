// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/gittuf/gittuf/internal/cedar"
	"github.com/gittuf/gittuf/internal/common"
	"github.com/gittuf/gittuf/internal/signerverifier/gpg"
	tufv01 "github.com/gittuf/gittuf/internal/tuf/v01"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
	"github.com/stretchr/testify/assert"
)

const forbidMainUpdates = `forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { resource.path == "refs/heads/main" };`

const forbidMainUnlessReleaseTeam = `forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { resource.path == "refs/heads/main" }
unless { principal in Gittuf::Group::"release-team" };`

const forbidNothing = `forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { resource.path == "refs/heads/never-pushed" };`

const forbidTagCreates = `forbid (
  principal,
  action == Gittuf::Action::"create",
  resource is Gittuf::GitRef
) when { resource.path like "refs/tags/*" };`

const forbidFilePath1 = `forbid (
  principal,
  action,
  resource is Gittuf::FilePath
) when { resource.path == "1" };`

const forbidFilePath999 = `forbid (
  principal,
  action,
  resource is Gittuf::FilePath
) when { resource.path == "999" };`

func gpgPrincipalID(t *testing.T) string {
	t.Helper()
	gpgKeyR, err := gpg.LoadGPGKeyFromBytes(gpgPubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	return tufv01.NewKeyFromSSLibKey(gpgKeyR).KeyID
}

func TestApplyCedarVeto(t *testing.T) {
	t.Parallel()

	refName := "refs/heads/main"

	t.Run("matched forbid vetoes entry", func(t *testing.T) {
		t.Parallel()

		repo, state := createTestRepositoryWithCedarPolicy(t, forbidMainUpdates, nil)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.ErrorIs(t, err, ErrCedarPolicyViolation)
	})

	t.Run("non-matching forbid leaves entry valid", func(t *testing.T) {
		t.Parallel()

		repo, state := createTestRepositoryWithCedarPolicy(t, forbidNothing, nil)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.Nil(t, err)
	})

	t.Run("unless clause exempts group member", func(t *testing.T) {
		t.Parallel()

		groups := map[string][]string{"release-team": {gpgPrincipalID(t)}}
		repo, state := createTestRepositoryWithCedarPolicy(t, forbidMainUnlessReleaseTeam, groups)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.Nil(t, err)
	})

	t.Run("unless clause does not exempt non-member", func(t *testing.T) {
		t.Parallel()

		groups := map[string][]string{"release-team": {"someone-else"}}
		repo, state := createTestRepositoryWithCedarPolicy(t, forbidMainUnlessReleaseTeam, groups)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.ErrorIs(t, err, ErrCedarPolicyViolation)
	})

	t.Run("no cedar policies is a no-op", func(t *testing.T) {
		t.Parallel()

		repo, state := createTestRepository(t, createTestStateWithPolicy)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.Nil(t, err)
	})

	t.Run("tag forbid vetoes tag entry", func(t *testing.T) {
		t.Parallel()

		// forbidTagCreates forbids any principal from creating a tag ref.
		repo, state := createTestRepositoryWithCedarPolicy(t, forbidTagCreates, nil)

		// Push a commit to main first so the tag has a target.
		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		mainEntry := rsl.NewReferenceEntry(refName, commitIDs[0])
		mainEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, mainEntry, gpgKeyBytes)

		tagName := "v1"
		tagID := common.CreateTestSignedTag(t, repo, tagName, commitIDs[0], gpgKeyBytes)

		tagEntry := rsl.NewReferenceEntry(gitinterface.TagReferenceName(tagName), tagID)
		tagEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, tagEntry, gpgKeyBytes)

		// verifyEntry dispatches to verifyTagEntry which runs applyCedarVeto.
		err := verifyEntry(testCtx, repo, state, nil, tagEntry)
		assert.ErrorIs(t, err, ErrCedarPolicyViolation)
	})

	t.Run("tag entry passes when cedar does not forbid it", func(t *testing.T) {
		t.Parallel()

		// forbidNothing never matches, so the tag entry should pass.
		repo, state := createTestRepositoryWithCedarPolicy(t, forbidNothing, nil)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		mainEntry := rsl.NewReferenceEntry(refName, commitIDs[0])
		mainEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, mainEntry, gpgKeyBytes)

		tagName := "v2"
		tagID := common.CreateTestSignedTag(t, repo, tagName, commitIDs[0], gpgKeyBytes)

		tagEntry := rsl.NewReferenceEntry(gitinterface.TagReferenceName(tagName), tagID)
		tagEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, tagEntry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, tagEntry)
		assert.Nil(t, err)
	})

	t.Run("file path forbid vetoes entry touching forbidden file", func(t *testing.T) {
		t.Parallel()

		// AddNTestCommitsToSpecifiedRef with n=1 produces a commit that touches
		// file "1", so forbidFilePath1 should veto it.
		repo, state := createTestRepositoryWithCedarPolicy(t, forbidFilePath1, nil)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.ErrorIs(t, err, ErrCedarPolicyViolation)
	})

	t.Run("file path forbid does not veto entry without forbidden file", func(t *testing.T) {
		t.Parallel()

		// forbidFilePath999 forbids file "999" which is never produced by the
		// test helper, so the entry should pass.
		repo, state := createTestRepositoryWithCedarPolicy(t, forbidFilePath999, nil)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		err := verifyEntry(testCtx, repo, state, nil, entry)
		assert.Nil(t, err)
	})
}

func TestCedarOperationsForEntry(t *testing.T) {
	t.Parallel()

	refName := "refs/heads/main"

	t.Run("first entry yields ActionCreate with file ops", func(t *testing.T) {
		t.Parallel()

		repo, _ := createTestRepository(t, createTestStateWithPolicy)

		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 2, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[1])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, entry, gpgKeyBytes)

		ops, err := cedarOperationsForEntry(repo, entry)
		assert.Nil(t, err)
		assert.Equal(t, cedar.Operation{Action: cedar.ActionCreate, ResourcePath: refName}, ops[0])
		assert.GreaterOrEqual(t, len(ops), 2)
		assert.True(t, ops[1].IsFilePath)
	})

	t.Run("second entry for same ref yields ActionUpdate", func(t *testing.T) {
		t.Parallel()

		repo, _ := createTestRepository(t, createTestStateWithPolicy)

		// First push — this becomes the create entry recorded in the RSL.
		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		firstEntry := rsl.NewReferenceEntry(refName, commitIDs[0])
		firstEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, firstEntry, gpgKeyBytes)

		// Second push — the RSL now has a prior entry for this ref, so this is an update.
		commitIDs2 := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		secondEntry := rsl.NewReferenceEntry(refName, commitIDs2[0])
		secondEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, secondEntry, gpgKeyBytes)

		ops, err := cedarOperationsForEntry(repo, secondEntry)
		assert.Nil(t, err)
		assert.Equal(t, cedar.ActionUpdate, ops[0].Action)
	})

	t.Run("deletion entry yields exactly one ActionDelete op", func(t *testing.T) {
		t.Parallel()

		repo, _ := createTestRepository(t, createTestStateWithPolicy)

		// Create at least one real entry for the ref first.
		commitIDs := common.AddNTestCommitsToSpecifiedRef(t, repo, refName, 1, gpgKeyBytes)
		firstEntry := rsl.NewReferenceEntry(refName, commitIDs[0])
		firstEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, firstEntry, gpgKeyBytes)

		// A deletion entry has a zero TargetID.
		deleteEntry := rsl.NewReferenceEntry(refName, gitinterface.ZeroHash)
		deleteEntry.ID = common.CreateTestRSLReferenceEntryCommit(t, repo, deleteEntry, gpgKeyBytes)

		ops, err := cedarOperationsForEntry(repo, deleteEntry)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(ops))
		assert.Equal(t, cedar.Operation{Action: cedar.ActionDelete, ResourcePath: refName}, ops[0])
	})
}
