// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package cedar applies Cedar policies declared in gittuf metadata over a
// change context, with forbid-only veto semantics: a change that gittuf's own
// verification permits is rejected only when an explicit forbid policy
// matches. Permit statements have no effect; exceptions are expressed as
// `unless` clauses on forbids.
//
// The entity model (the "Gittuf" Cedar namespace):
//
//	entity User in [Group];         // ID = gittuf principal ID
//	entity Group;                   // declared in root metadata groups
//	entity GitRef  = { path: String };
//	entity FilePath = { path: String };
//	action "create", "update", "delete" appliesTo {
//	    principal: User,
//	    resource: [GitRef, FilePath],
//	    context: { actor: User },
//	}
package cedar

import (
	"fmt"
	"slices"

	cedargo "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

const (
	UserEntityType     = types.EntityType("Gittuf::User")
	GroupEntityType    = types.EntityType("Gittuf::Group")
	GitRefEntityType   = types.EntityType("Gittuf::GitRef")
	FilePathEntityType = types.EntityType("Gittuf::FilePath")
	ActionEntityType   = types.EntityType("Gittuf::Action")

	ActionCreate = "create"
	ActionUpdate = "update"
	ActionDelete = "delete"
)

// Operation is a single unit of change under evaluation: an action performed
// on a Git reference or a file path.
type Operation struct {
	Action       string // ActionCreate, ActionUpdate or ActionDelete
	IsFilePath   bool   // resource is a FilePath instead of a GitRef
	ResourcePath string
}

// Violation reports a matched forbid: the operation, the acting principal and
// the IDs of the forbid policies that fired.
type Violation struct {
	PolicyIDs []string
	Principal string
	Operation Operation
}

// PolicySet accumulates parsed Cedar policies from the blobs declared in
// gittuf metadata.
type PolicySet struct {
	ps *cedargo.PolicySet
}

// NewPolicySet returns an empty PolicySet.
func NewPolicySet() *PolicySet {
	return &PolicySet{ps: cedargo.NewPolicySet()}
}

// Validate parses source as Cedar policy syntax, returning any parse error.
// Used at add time so authoring mistakes fail before they reach metadata.
func Validate(name string, source []byte) error {
	_, err := cedargo.NewPolicyListFromBytes(name, source)
	return err
}

// AddPolicies parses source and registers each policy statement under the ID
// "<name>/policy<N>", so violations can name the originating metadata entry.
// Each name may only be added once; metadata enforces this too, but reusing a
// name here would silently replace the earlier statements.
func (s *PolicySet) AddPolicies(name string, source []byte) error {
	parsed, err := cedargo.NewPolicyListFromBytes(name, source)
	if err != nil {
		return err
	}

	for i, p := range parsed {
		id := types.PolicyID(fmt.Sprintf("%s/policy%d", name, i))
		if !s.ps.Add(id, p) {
			return fmt.Errorf("cedar policy %q already added", id)
		}
	}
	return nil
}

// BuildEntities constructs the Cedar entity graph for an evaluation: a User
// per principal ID (with the groups that contain it as parents), a Group per
// declared group, and a GitRef/FilePath entity per operation resource with
// its path attribute set.
func BuildEntities(principalIDs []string, groups map[string][]string, ops []Operation) types.EntityMap {
	entities := types.EntityMap{}

	memberOf := map[string][]types.EntityUID{}
	for group, members := range groups {
		groupUID := types.NewEntityUID(GroupEntityType, types.String(group))
		entities[groupUID] = types.Entity{
			UID:        groupUID,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{}),
		}
		for _, member := range members {
			memberOf[member] = append(memberOf[member], groupUID)
		}
	}

	for _, principalID := range principalIDs {
		userUID := types.NewEntityUID(UserEntityType, types.String(principalID))
		entities[userUID] = types.Entity{
			UID:        userUID,
			Parents:    types.NewEntityUIDSet(memberOf[principalID]...),
			Attributes: types.NewRecord(types.RecordMap{}),
		}
	}

	for _, op := range ops {
		uid := resourceUID(op)
		entities[uid] = types.Entity{
			UID:        uid,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"path": types.String(op.ResourcePath)}),
		}
	}

	return entities
}

func resourceUID(op Operation) types.EntityUID {
	entityType := GitRefEntityType
	if op.IsFilePath {
		entityType = FilePathEntityType
	}
	return types.NewEntityUID(entityType, types.String(op.ResourcePath))
}

// Veto evaluates each operation for the acting principal and returns a
// Violation per operation that an explicit forbid matched. A Deny without
// matched forbids (i.e. no permit matched) is NOT a violation: gittuf's own
// verification remains authoritative and Cedar only vetoes.
func (s *PolicySet) Veto(principalID string, entities types.EntityMap, ops []Operation) []Violation {
	principal := types.NewEntityUID(UserEntityType, types.String(principalID))

	var violations []Violation
	for _, op := range ops {
		request := cedargo.Request{
			Principal: principal,
			Action:    types.NewEntityUID(ActionEntityType, types.String(op.Action)),
			Resource:  resourceUID(op),
			Context:   types.NewRecord(types.RecordMap{"actor": principal}),
		}

		decision, diagnostic := cedargo.Authorize(s.ps, entities, request)
		if len(diagnostic.Errors) > 0 {
			// A policy errored during evaluation (e.g. it references an
			// attribute the entity model does not provide). Fail closed: an
			// enforcement primitive must not silently pass on broken policies.
			policyIDs := make([]string, 0, len(diagnostic.Errors))
			for _, evalErr := range diagnostic.Errors {
				policyIDs = append(policyIDs, string(evalErr.PolicyID))
			}
			slices.Sort(policyIDs)
			violations = append(violations, Violation{
				PolicyIDs: policyIDs,
				Principal: principalID,
				Operation: op,
			})
			continue
		}
		if decision == cedargo.Deny && len(diagnostic.Reasons) > 0 {
			policyIDs := make([]string, 0, len(diagnostic.Reasons))
			for _, reason := range diagnostic.Reasons {
				policyIDs = append(policyIDs, string(reason.PolicyID))
			}
			slices.Sort(policyIDs)
			violations = append(violations, Violation{
				PolicyIDs: policyIDs,
				Principal: principalID,
				Operation: op,
			})
		}
	}

	return violations
}
