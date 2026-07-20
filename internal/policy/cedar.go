// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gittuf/gittuf/internal/cedar"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
)

var ErrCedarPolicyViolation = errors.New("change forbidden by cedar policy")

// unknownCedarPrincipalID is the Cedar user an entry maps to when its
// signature does not resolve to any declared principal. It is not a member of
// any group, so group carve-outs ("unless principal in ...") correctly do not
// apply to it.
const unknownCedarPrincipalID = "gittuf-cedar-unknown-principal"

// applyCedarVeto evaluates the Cedar policies declared in the root metadata
// over the entry's change context. Existing gittuf verification remains
// authoritative: the entry is rejected only when an explicit forbid matches
// (veto semantics), so permit statements have no effect.
func applyCedarVeto(ctx context.Context, repo *gitinterface.Repository, policy *State, entry *rsl.ReferenceEntry) error {
	if len(policy.CedarPolicies) == 0 {
		return nil
	}

	policySet, err := policy.CedarPolicySet(repo)
	if err != nil {
		return err
	}

	ops, err := cedarOperationsForEntry(repo, entry)
	if err != nil {
		return err
	}

	actingPrincipalIDs := policy.resolveEntrySigners(ctx, entry)

	allPrincipalIDs := make([]string, 0, len(policy.allPrincipals)+len(actingPrincipalIDs))
	for principalID := range policy.allPrincipals {
		allPrincipalIDs = append(allPrincipalIDs, principalID)
	}
	allPrincipalIDs = append(allPrincipalIDs, actingPrincipalIDs...)

	entities := cedar.BuildEntities(allPrincipalIDs, policy.Groups, ops)

	for _, principalID := range actingPrincipalIDs {
		if violations := policySet.Veto(principalID, entities, ops); len(violations) > 0 {
			v := violations[0]
			return fmt.Errorf("%w: policy '%s' forbids '%s' on '%s' for principal '%s'",
				ErrCedarPolicyViolation, strings.Join(v.PolicyIDs, ", "), v.Operation.Action, v.Operation.ResourcePath, principalID)
		}
	}

	return nil
}

// CedarPolicySet returns the parsed Cedar policies declared in the state,
// reading and parsing the policy blobs on first use and memoizing the result:
// the declared policies are immutable for a given state, and verification
// walks apply the same state to many RSL entries. preprocess resets the memo
// whenever the declared policies change.
func (s *State) CedarPolicySet(repo *gitinterface.Repository) (*cedar.PolicySet, error) {
	if s.cedarPolicySet != nil {
		return s.cedarPolicySet, nil
	}

	policySet := cedar.NewPolicySet()
	for _, cedarPolicy := range s.CedarPolicies {
		contents, err := repo.ReadBlob(cedarPolicy.GetBlobID())
		if err != nil {
			return nil, fmt.Errorf("unable to read cedar policy '%s': %w", cedarPolicy.ID(), err)
		}
		if err := policySet.AddPolicies(cedarPolicy.ID(), contents); err != nil {
			return nil, fmt.Errorf("unable to parse cedar policy '%s': %w", cedarPolicy.ID(), err)
		}
	}

	s.cedarPolicySet = policySet
	return policySet, nil
}

// resolveEntrySigners maps the RSL entry's git signature to a declared
// principal ID. RSL entries are single-signer git commits, so this resolves
// to the first declared principal whose key verifies the signature; principals
// sharing a key are indistinguishable here. When nothing matches, the entry
// acts as the unknown Cedar principal.
func (s *State) resolveEntrySigners(ctx context.Context, entry *rsl.ReferenceEntry) []string {
	if len(s.allPrincipals) == 0 {
		return []string{unknownCedarPrincipalID}
	}

	verifier := &SignatureVerifier{
		repository:         s.repository,
		name:               tuf.ExhaustiveVerifierName,
		threshold:          1,
		verifyExhaustively: true,
	}
	for _, principal := range s.allPrincipals {
		verifier.principals = append(verifier.principals, principal)
	}

	principalIDs, err := verifier.Verify(ctx, gitHash(entry.ID), nil)
	if err != nil || principalIDs == nil || principalIDs.Len() == 0 {
		slog.Debug("RSL entry signature does not match a declared principal, using unknown cedar principal...")
		return []string{unknownCedarPrincipalID}
	}
	return principalIDs.Contents()
}

// cedarOperationsForEntry derives the Cedar operations for an RSL reference
// entry: the ref-level create/update/delete plus, for branches, an update per
// file path changed by the commits the entry introduces. Per the v1 design,
// file-level changes are always reported as ActionUpdate regardless of whether
// the file is being created or deleted.
func cedarOperationsForEntry(repo *gitinterface.Repository, entry *rsl.ReferenceEntry) ([]cedar.Operation, error) {
	if entry.TargetID.IsZero() {
		return []cedar.Operation{{Action: cedar.ActionDelete, ResourcePath: entry.RefName}}, nil
	}

	action := cedar.ActionUpdate
	if _, _, err := rsl.GetLatestReferenceUpdaterEntry(rsl.NewRepositoryRSLStorerAdapter(repo), rsl.ForReference(entry.RefName), rsl.BeforeEntryID(entry.ID)); err != nil {
		if !errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return nil, err
		}
		action = cedar.ActionCreate
	}

	ops := []cedar.Operation{{Action: action, ResourcePath: entry.RefName}}

	if strings.HasPrefix(entry.RefName, gitinterface.TagRefPrefix) {
		return ops, nil
	}

	commitIDs, err := getCommits(repo, entry)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, commitID := range commitIDs {
		paths, err := repo.GetFilePathsChangedByCommit(commitID)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			if seen[path] {
				continue
			}
			seen[path] = true
			ops = append(ops, cedar.Operation{Action: cedar.ActionUpdate, IsFilePath: true, ResourcePath: path})
		}
	}

	return ops, nil
}
