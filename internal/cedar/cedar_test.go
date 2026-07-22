// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package cedar

import (
	"testing"

	"github.com/cedar-policy/cedar-go/types"
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

const forbidTagsUnlessReleaseTeam = `forbid (
  principal,
  action == Gittuf::Action::"create",
  resource is Gittuf::GitRef
) when { resource.path like "refs/tags/*" }
unless { principal in Gittuf::Group::"release-team" };`

const permitEverything = `permit (principal, action, resource);`

func TestVeto(t *testing.T) {
	t.Parallel()

	createTag := Operation{Action: ActionCreate, ResourcePath: "refs/tags/v1.0.0"}
	updateMain := Operation{Action: ActionUpdate, ResourcePath: "refs/heads/main"}
	groups := map[string][]string{"release-team": {"alice"}}

	t.Run("forbid matches", func(t *testing.T) {
		t.Parallel()

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("no-tags", []byte(forbidTagsPolicy)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice"}, nil, []Operation{createTag})

		violations := policySet.Veto("alice", entities, []Operation{createTag})
		assert.Len(t, violations, 1)
		assert.Equal(t, []string{"no-tags/policy0"}, violations[0].PolicyIDs)
		assert.Equal(t, createTag, violations[0].Operation)
	})

	t.Run("forbid does not match other namespace", func(t *testing.T) {
		t.Parallel()

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("no-tags", []byte(forbidTagsPolicy)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice"}, nil, []Operation{updateMain})

		violations := policySet.Veto("alice", entities, []Operation{updateMain})
		assert.Empty(t, violations)
	})

	t.Run("unless clause carves out group members", func(t *testing.T) {
		t.Parallel()

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("no-tags", []byte(forbidTagsUnlessReleaseTeam)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice", "bob"}, groups, []Operation{createTag})

		assert.Empty(t, policySet.Veto("alice", entities, []Operation{createTag}))
		assert.Len(t, policySet.Veto("bob", entities, []Operation{createTag}), 1)
	})

	t.Run("unknown principal is not in any group", func(t *testing.T) {
		t.Parallel()

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("no-tags", []byte(forbidTagsUnlessReleaseTeam)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice"}, groups, []Operation{createTag})

		assert.Len(t, policySet.Veto("someone-else", entities, []Operation{createTag}), 1)
	})

	t.Run("permit statements have no effect", func(t *testing.T) {
		t.Parallel()

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("allow-all", []byte(permitEverything)); err != nil {
			t.Fatal(err)
		}
		if err := policySet.AddPolicies("no-tags", []byte(forbidTagsPolicy)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice"}, nil, []Operation{createTag, updateMain})

		assert.Len(t, policySet.Veto("alice", entities, []Operation{createTag}), 1)
		assert.Empty(t, policySet.Veto("alice", entities, []Operation{updateMain}))
	})

	t.Run("policy evaluation error fails closed", func(t *testing.T) {
		t.Parallel()

		const forbidBrokenAttribute = `forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { resource.owner == "root" };`

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("broken", []byte(forbidBrokenAttribute)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice"}, nil, []Operation{updateMain})

		violations := policySet.Veto("alice", entities, []Operation{updateMain})
		assert.Len(t, violations, 1)
		assert.Equal(t, []string{"broken/policy0"}, violations[0].PolicyIDs)
	})

	t.Run("context actor is available to policies", func(t *testing.T) {
		t.Parallel()

		const forbidActorAlice = `forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { context.actor == Gittuf::User::"alice" };`

		policySet := NewPolicySet()
		if err := policySet.AddPolicies("no-alice", []byte(forbidActorAlice)); err != nil {
			t.Fatal(err)
		}
		entities := BuildEntities([]string{"alice", "bob"}, nil, []Operation{updateMain})

		assert.Len(t, policySet.Veto("alice", entities, []Operation{updateMain}), 1)
		assert.Empty(t, policySet.Veto("bob", entities, []Operation{updateMain}))
	})
}

func TestBuildEntities(t *testing.T) {
	t.Parallel()

	groups := map[string][]string{
		"admins": {"alice"},
	}
	updateMain := Operation{Action: ActionUpdate, ResourcePath: "refs/heads/main"}
	updateFile := Operation{Action: ActionUpdate, ResourcePath: "src/main.go", IsFilePath: true}

	entities := BuildEntities([]string{"alice", "bob"}, groups, []Operation{updateMain, updateFile})

	adminsUID := types.NewEntityUID(GroupEntityType, types.String("admins"))
	aliceUID := types.NewEntityUID(UserEntityType, types.String("alice"))
	bobUID := types.NewEntityUID(UserEntityType, types.String("bob"))
	gitRefUID := types.NewEntityUID(GitRefEntityType, types.String("refs/heads/main"))
	filePathUID := types.NewEntityUID(FilePathEntityType, types.String("src/main.go"))

	// Group entity exists with empty parents.
	adminsEntity, ok := entities[adminsUID]
	assert.True(t, ok)
	assert.Equal(t, 0, adminsEntity.Parents.Len())

	// User in a group has the group UID as parent.
	aliceEntity, ok := entities[aliceUID]
	assert.True(t, ok)
	assert.True(t, aliceEntity.Parents.Contains(adminsUID))

	// User not in any group has empty parents.
	bobEntity, ok := entities[bobUID]
	assert.True(t, ok)
	assert.Equal(t, 0, bobEntity.Parents.Len())

	// Non-filepath operation yields a GitRef entity with path attribute.
	gitRefEntity, ok := entities[gitRefUID]
	assert.True(t, ok)
	pathVal, exists := gitRefEntity.Attributes.Get("path")
	assert.True(t, exists)
	assert.Equal(t, types.String("refs/heads/main"), pathVal)

	// Filepath operation yields a FilePath entity with path attribute.
	filePathEntity, ok := entities[filePathUID]
	assert.True(t, ok)
	pathVal, exists = filePathEntity.Attributes.Get("path")
	assert.True(t, exists)
	assert.Equal(t, types.String("src/main.go"), pathVal)
}
