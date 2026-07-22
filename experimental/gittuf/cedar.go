// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cedar"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/gittuf/gittuf/internal/policy"
	policyopts "github.com/gittuf/gittuf/internal/policy/options/policy"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
)

var ErrNoCedarPolicyName = errors.New("no cedar policy name provided")

// Cedar actions for ProposedRefUpdate. These are the only values
// EvaluateCedarVetoes accepts.
const (
	CedarActionCreate = cedar.ActionCreate
	CedarActionUpdate = cedar.ActionUpdate
	CedarActionDelete = cedar.ActionDelete
)

// AddCedarPolicy validates policyBytes as Cedar policy syntax, writes it as a
// blob and declares it in the root of trust metadata. The policy is enforced
// as a forbid-only veto during verification.
func (r *Repository) AddCedarPolicy(ctx context.Context, signer sslibdsse.SignerVerifier, policyName string, policyBytes []byte, signCommit bool, opts ...trustpolicyopts.Option) error {
	if !dev.InDevMode() {
		return dev.ErrNotInDevMode
	}

	if signCommit {
		slog.Debug("Checking if Git signing is configured...")
		err := r.r.CanSign()
		if err != nil {
			return err
		}
	}

	if policyName == "" {
		return ErrNoCedarPolicyName
	}

	if err := cedar.Validate(policyName, policyBytes); err != nil {
		return fmt.Errorf("invalid cedar policy '%s': %w", policyName, err)
	}

	options := &trustpolicyopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	rootKeyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
	if err != nil {
		return err
	}

	rootMetadata, err := r.loadRootMetadata(state, rootKeyID)
	if err != nil {
		return err
	}

	var hashes = make(map[string]string, 2)
	blobID, err := r.r.WriteBlob(policyBytes)
	if err != nil {
		return err
	}
	hashes[gitinterface.GitBlobHashName] = blobID.String()

	sha256Hash := sha256.New()
	sha256Hash.Write(policyBytes)
	hashes[gitinterface.SHA256HashName] = hex.EncodeToString(sha256Hash.Sum(nil))

	slog.Debug("Adding cedar policy to root metadata...")
	cedarPolicy, err := rootMetadata.AddCedarPolicy(policyName, hashes)
	if err != nil {
		return err
	}

	state.CedarPolicies = append(state.CedarPolicies, cedarPolicy)

	commitMessage := fmt.Sprintf("Add cedar policy '%s' to root metadata", policyName)
	return r.updateRootMetadata(ctx, state, signer, rootMetadata, commitMessage, options.CreateRSLEntry, signCommit)
}

// RemoveCedarPolicy removes a cedar policy declared in the root of trust metadata.
func (r *Repository) RemoveCedarPolicy(ctx context.Context, signer sslibdsse.SignerVerifier, policyName string, signCommit bool, opts ...trustpolicyopts.Option) error {
	if !dev.InDevMode() {
		return dev.ErrNotInDevMode
	}

	if signCommit {
		slog.Debug("Checking if Git signing is configured...")
		err := r.r.CanSign()
		if err != nil {
			return err
		}
	}

	options := &trustpolicyopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	rootKeyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
	if err != nil {
		return err
	}

	rootMetadata, err := r.loadRootMetadata(state, rootKeyID)
	if err != nil {
		return err
	}

	slog.Debug("Removing cedar policy from root metadata...")
	if err := rootMetadata.RemoveCedarPolicy(policyName); err != nil {
		return err
	}

	updatedPolicies := make([]tuf.CedarPolicy, 0, len(state.CedarPolicies))
	for _, p := range state.CedarPolicies {
		if p.ID() != policyName {
			updatedPolicies = append(updatedPolicies, p)
		}
	}
	state.CedarPolicies = updatedPolicies

	commitMessage := fmt.Sprintf("Remove cedar policy '%s' from root metadata", policyName)
	return r.updateRootMetadata(ctx, state, signer, rootMetadata, commitMessage, options.CreateRSLEntry, signCommit)
}

// ListCedarPolicies returns the cedar policies declared in the specified policy ref.
func (r *Repository) ListCedarPolicies(ctx context.Context, targetRef string) ([]tuf.CedarPolicy, error) {
	if !strings.HasPrefix(targetRef, "refs/gittuf/") {
		targetRef = "refs/gittuf/" + targetRef
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, targetRef)
	if err != nil {
		return nil, err
	}

	return state.CedarPolicies, nil
}

// AddGroup declares a principal group in the root of trust metadata for use in cedar policies.
func (r *Repository) AddGroup(ctx context.Context, signer sslibdsse.SignerVerifier, groupName string, principalIDs []string, signCommit bool, opts ...trustpolicyopts.Option) error {
	if !dev.InDevMode() {
		return dev.ErrNotInDevMode
	}

	if signCommit {
		slog.Debug("Checking if Git signing is configured...")
		err := r.r.CanSign()
		if err != nil {
			return err
		}
	}

	options := &trustpolicyopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	rootKeyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
	if err != nil {
		return err
	}

	rootMetadata, err := r.loadRootMetadata(state, rootKeyID)
	if err != nil {
		return err
	}

	slog.Debug("Adding group to root metadata...")
	if err := rootMetadata.AddGroup(groupName, principalIDs); err != nil {
		return err
	}

	if state.Groups == nil {
		state.Groups = make(map[string][]string)
	}
	state.Groups[groupName] = principalIDs

	commitMessage := fmt.Sprintf("Add group '%s' to root metadata", groupName)
	return r.updateRootMetadata(ctx, state, signer, rootMetadata, commitMessage, options.CreateRSLEntry, signCommit)
}

// RemoveGroup removes a principal group from the root of trust metadata.
func (r *Repository) RemoveGroup(ctx context.Context, signer sslibdsse.SignerVerifier, groupName string, signCommit bool, opts ...trustpolicyopts.Option) error {
	if !dev.InDevMode() {
		return dev.ErrNotInDevMode
	}

	if signCommit {
		slog.Debug("Checking if Git signing is configured...")
		err := r.r.CanSign()
		if err != nil {
			return err
		}
	}

	options := &trustpolicyopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	rootKeyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef, policyopts.BypassRSL())
	if err != nil {
		return err
	}

	rootMetadata, err := r.loadRootMetadata(state, rootKeyID)
	if err != nil {
		return err
	}

	slog.Debug("Removing group from root metadata...")
	if err := rootMetadata.RemoveGroup(groupName); err != nil {
		return err
	}

	delete(state.Groups, groupName)

	commitMessage := fmt.Sprintf("Remove group '%s' from root metadata", groupName)
	return r.updateRootMetadata(ctx, state, signer, rootMetadata, commitMessage, options.CreateRSLEntry, signCommit)
}

// ProposedRefUpdate describes a reference update that has not happened yet,
// for pre-apply Cedar evaluation (e.g. by a server deciding whether to accept
// a push).
type ProposedRefUpdate struct {
	RefName     string
	Action      string // must be one of CedarActionCreate, CedarActionUpdate, or CedarActionDelete
	PrincipalID string
}

// CedarViolation reports a proposed update that a forbid policy matched.
type CedarViolation struct {
	RefName   string
	Action    string
	PolicyIDs []string
}

// EvaluateCedarVetoes evaluates the Cedar policies declared in the currently
// applied policy against proposed reference updates. It returns one violation
// per vetoed update; no declared policies (or no applied policy at all) means
// no violations. Unlike the management APIs this is a verification path and
// is not gated on dev mode. Violations are returned in the same order as the
// corresponding updates.
func (r *Repository) EvaluateCedarVetoes(ctx context.Context, updates []ProposedRefUpdate) ([]CedarViolation, error) {
	for _, update := range updates {
		switch update.Action {
		case CedarActionCreate, CedarActionUpdate, CedarActionDelete:
		default:
			return nil, fmt.Errorf("invalid cedar action %q for ref %q", update.Action, update.RefName)
		}
	}

	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyRef)
	if err != nil {
		if errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return nil, nil
		}
		return nil, err
	}

	if len(state.CedarPolicies) == 0 {
		return nil, nil
	}

	policySet, err := state.CedarPolicySet(r.r)
	if err != nil {
		return nil, err
	}

	// Collect all principal IDs: those declared in the policy plus every
	// principal referenced in the proposed updates.
	principalSet := make(map[string]struct{})
	for id := range state.GetAllPrincipals() {
		principalSet[id] = struct{}{}
	}
	for _, u := range updates {
		if u.PrincipalID != "" {
			principalSet[u.PrincipalID] = struct{}{}
		}
	}
	principalIDs := make([]string, 0, len(principalSet))
	for id := range principalSet {
		principalIDs = append(principalIDs, id)
	}

	// Build all operations first and construct the entity graph once; the
	// group+principal graph is identical across updates and BuildEntities
	// populates resource entities for every op.
	allOps := make([]cedar.Operation, len(updates))
	for i, update := range updates {
		allOps[i] = cedar.Operation{Action: update.Action, ResourcePath: update.RefName}
	}
	entities := cedar.BuildEntities(principalIDs, state.Groups, allOps)

	var violations []CedarViolation
	for i, update := range updates {
		for _, v := range policySet.Veto(update.PrincipalID, entities, []cedar.Operation{allOps[i]}) {
			violations = append(violations, CedarViolation{
				RefName:   update.RefName,
				Action:    update.Action,
				PolicyIDs: v.PolicyIDs,
			})
		}
	}

	return violations, nil
}
