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
