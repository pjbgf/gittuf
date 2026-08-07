// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy is a public, storage-parameterized façade over gittuf's policy
// and root-of-trust engine. The engine itself (internal/policy, internal/tuf,
// internal/signerverifier) is parameterized by pkg/gitstore.Storer, but the
// only public entry point (experimental/gittuf.Repository) is hard-wired to an
// on-disk Git repository. This package re-exposes authoring, verification, and
// inspection of gittuf policy over any gitstore.Storer implementation so that
// external modules can drive gittuf trust over their own storage backend.
//
// Trust model of the façade:
//
//   - Bootstrap authors a root of trust and a single top-level "targets" rule
//     file, stages them on refs/gittuf/policy-staging, records an RSL entry, and
//     applies to refs/gittuf/policy. The root and targets DSSE envelopes are
//     signed with the root private key. Commit objects are not Git-signed. Trust
//     flows from the DSSE signatures plus the RSL entry signatures.
//   - The root pins an application-defined repository identifier into a signed
//     custom field and authorizes the RSL signer public keys to write the given
//     ref patterns via the top-level targets rule file.
//   - VerifyRef checks that the latest RSL entry for a ref is signed by an
//     authorized principal, per the applied policy.
package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/gittuf/gittuf/internal/tuf"
	tufv02 "github.com/gittuf/gittuf/internal/tuf/v02"
	"github.com/gittuf/gittuf/pkg/githash"
	"github.com/gittuf/gittuf/pkg/gitstore"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"golang.org/x/crypto/ssh"
)

// CustomFieldRepositoryID is the root metadata custom field key under which
// Bootstrap pins the caller-provided repository identifier.
const CustomFieldRepositoryID = "custom.entire.io/repository"

// rslSignerRuleName is the name of the top-level targets rule that authorizes
// the RSL signer principals to write the requested ref patterns.
const rslSignerRuleName = "authorize-rsl-signers"

// BootstrapParams configures a single-shot bootstrap of the root of trust and
// the top-level targets rule file. It takes raw ed25519 key material only, so no
// exported field names a gittuf internal type. Bootstrap builds the gittuf
// principals and signer internally.
type BootstrapParams struct {
	// RepoID is pinned into the root metadata custom field
	// CustomFieldRepositoryID.
	RepoID string

	// RootPrivateKey is the fleet root signer. It signs the root and top-level
	// targets DSSE envelopes and must correspond to one of RootPublicKeys.
	RootPrivateKey ed25519.PrivateKey

	// RootPublicKeys are the public keys trusted for the root role. In the MVP
	// these are also authorized as the top-level targets (policy) key.
	RootPublicKeys []ed25519.PublicKey

	// RootThreshold is the number of root signatures required. Also used as the
	// top-level targets threshold in the MVP.
	RootThreshold int

	// RSLSignerPublicKeys are the cluster RSL signer public keys authorized to
	// write the RefPatterns, i.e. their keys may sign RSL entries for those refs.
	RSLSignerPublicKeys []ed25519.PublicKey

	// RefPatterns are the gittuf rule patterns the RSL signers are authorized
	// for, e.g. "git:refs/*".
	RefPatterns []string

	// Expires sets the expiry recorded in the root and targets metadata.
	Expires time.Time
}

// newED25519Signer builds a DSSE SignerVerifier from a raw ed25519 private key
// without touching the filesystem. The signer produces SSH-format signatures
// (armored sshsig, SHA-512, namespace "git") so that the resulting signatures
// verify against the SSH principal returned by newED25519Principal for the
// matching public key. Its KeyID equals that principal's ID.
func newED25519Signer(priv ed25519.PrivateKey) (sslibdsse.SignerVerifier, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	sshSigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to create ssh signer from ed25519 key: %w", err)
	}

	key := sshSLibKey(sshSigner.PublicKey())
	return newSSHSignerVerifier(sshSigner, key)
}

// newED25519Principal builds a gittuf principal from a raw ed25519 public key
// without touching the filesystem. The principal carries an SSH-type key so
// that SSH-signed Git objects (RSL entries) and SSH-format DSSE envelopes both
// verify against it. Its ID is the SSH SHA-256 fingerprint of the key.
func newED25519Principal(pub ed25519.PublicKey) (tuf.Principal, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to create ssh public key from ed25519 key: %w", err)
	}

	return tufv02.NewKeyFromSSLibKey(sshSLibKey(sshPub)), nil
}

// Bootstrap authors the root of trust and the top-level targets rule file over
// store, staging and applying them to refs/gittuf/policy. It returns the applied
// policy commit ID.
func Bootstrap(ctx context.Context, store gitstore.Storer, p BootstrapParams) (githash.Hash, error) {
	if p.RepoID == "" {
		return nil, fmt.Errorf("repository id must be provided")
	}
	if len(p.RootPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("root private key must be provided")
	}
	if len(p.RootPublicKeys) == 0 {
		return nil, fmt.Errorf("at least one root public key must be provided")
	}
	if p.RootThreshold < 1 {
		return nil, fmt.Errorf("root threshold must be at least 1")
	}
	if len(p.RSLSignerPublicKeys) == 0 {
		return nil, fmt.Errorf("at least one RSL signer public key must be provided")
	}
	if len(p.RefPatterns) == 0 {
		return nil, fmt.Errorf("at least one ref pattern must be provided")
	}

	rootSigner, err := newED25519Signer(p.RootPrivateKey)
	if err != nil {
		return nil, err
	}

	rootPrincipals, err := principalsFromPublicKeys(p.RootPublicKeys)
	if err != nil {
		return nil, err
	}

	rslPrincipals, err := principalsFromPublicKeys(p.RSLSignerPublicKeys)
	if err != nil {
		return nil, err
	}

	if _, err := store.GetReference(policy.PolicyRef); err == nil {
		return nil, fmt.Errorf("policy already initialized on %s", policy.PolicyRef)
	} else if !isReferenceNotFound(err) {
		return nil, err
	}

	rootMetadata, err := buildRootMetadata(p, rootPrincipals)
	if err != nil {
		return nil, err
	}

	rootEnv, err := dsse.CreateEnvelope(rootMetadata)
	if err != nil {
		return nil, err
	}
	rootEnv, err = dsse.SignEnvelope(ctx, rootEnv, rootSigner)
	if err != nil {
		return nil, err
	}

	targetsMetadata, err := buildTargetsMetadata(p, rslPrincipals)
	if err != nil {
		return nil, err
	}

	targetsEnv, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return nil, err
	}
	targetsEnv, err = dsse.SignEnvelope(ctx, targetsEnv, rootSigner)
	if err != nil {
		return nil, err
	}

	state := &policy.State{
		Metadata: &policy.StateMetadata{
			RootEnvelope:    rootEnv,
			TargetsEnvelope: targetsEnv,
		},
	}

	if err := state.Commit(store, "Bootstrap gittuf policy", true, false); err != nil {
		return nil, fmt.Errorf("unable to stage policy: %w", err)
	}

	if err := policy.Apply(ctx, store, false); err != nil {
		return nil, fmt.Errorf("unable to apply policy: %w", err)
	}

	appliedTip, err := store.GetReference(policy.PolicyRef)
	if err != nil {
		return nil, fmt.Errorf("unable to read applied policy reference: %w", err)
	}

	return appliedTip, nil
}

// VerifyRef verifies the latest RSL entry for ref against the applied policy on
// refs/gittuf/policy. It returns nil when the entry is signed by an authorized
// principal.
func VerifyRef(ctx context.Context, store gitstore.Storer, ref string) error {
	verifier := policy.NewPolicyVerifier(store)
	_, err := verifier.VerifyRef(ctx, ref)
	return err
}

// VerifyRefFromEntry verifies ref against the applied policy starting from the
// given RSL entry ID rather than the first entry. It does not require developer
// mode: unlike the experimental wrapper, the façade calls the engine directly.
func VerifyRefFromEntry(ctx context.Context, store gitstore.Storer, ref, entryID string) error {
	id, err := githash.NewHash(entryID)
	if err != nil {
		return err
	}

	verifier := policy.NewPolicyVerifier(store)
	_, err = verifier.VerifyRefFromEntry(ctx, ref, id)
	return err
}

// RootInfo reports facts about the applied root of trust.
type RootInfo struct {
	// RepoID is the value pinned into CustomFieldRepositoryID.
	RepoID string

	// Version is the root metadata version.
	Version int

	// RootKeyIDs are the principal IDs trusted for the root role.
	RootKeyIDs []string

	// AuthorizedRSLSigners are the principal IDs authorized to write refs via
	// the top-level targets rule file.
	AuthorizedRSLSigners []string
}

// InspectRoot loads the applied policy from refs/gittuf/policy and returns root
// facts. Loading verifies the metadata signatures against the trusted root, so
// this is a verified read: a load of tampered metadata fails.
func InspectRoot(ctx context.Context, store gitstore.Storer) (RootInfo, error) {
	state, err := policy.LoadCurrentState(ctx, store, policy.PolicyRef)
	if err != nil {
		return RootInfo{}, err
	}

	rootMetadata, err := state.GetRootMetadata(false)
	if err != nil {
		return RootInfo{}, err
	}

	rootPrincipals, err := rootMetadata.GetRootPrincipals()
	if err != nil {
		return RootInfo{}, err
	}

	info := RootInfo{
		RepoID:     rootMetadata.GetCustomFields()[CustomFieldRepositoryID],
		Version:    int(rootMetadata.GetVersion()),
		RootKeyIDs: principalIDs(rootPrincipals),
	}

	signers, err := authorizedRSLSigners(state)
	if err != nil {
		return RootInfo{}, err
	}
	info.AuthorizedRSLSigners = signers

	return info, nil
}

func buildRootMetadata(p BootstrapParams, rootPrincipals []tuf.Principal) (tuf.RootMetadata, error) {
	rootMetadata := tufv02.NewRootMetadata()
	rootMetadata.SetExpires(p.Expires.Format(time.RFC3339))

	for _, principal := range rootPrincipals {
		if err := rootMetadata.AddRootPrincipal(principal); err != nil {
			return nil, err
		}
	}
	if err := rootMetadata.UpdateRootThreshold(p.RootThreshold); err != nil {
		return nil, err
	}

	// MVP: the top-level targets (policy) key is the root key.
	for _, principal := range rootPrincipals {
		if err := rootMetadata.AddPrimaryRuleFilePrincipal(principal); err != nil {
			return nil, err
		}
	}
	if err := rootMetadata.UpdatePrimaryRuleFileThreshold(p.RootThreshold); err != nil {
		return nil, err
	}

	if err := rootMetadata.SetCustomField(CustomFieldRepositoryID, p.RepoID); err != nil {
		return nil, err
	}

	return rootMetadata, nil
}

func buildTargetsMetadata(p BootstrapParams, rslPrincipals []tuf.Principal) (tuf.TargetsMetadata, error) {
	targetsMetadata := tufv02.NewTargetsMetadata()
	targetsMetadata.SetExpires(p.Expires.Format(time.RFC3339))

	principalIDs := make([]string, 0, len(rslPrincipals))
	for _, principal := range rslPrincipals {
		if err := targetsMetadata.AddPrincipal(principal); err != nil {
			return nil, err
		}
		principalIDs = append(principalIDs, principal.ID())
	}

	if err := targetsMetadata.AddRule(rslSignerRuleName, principalIDs, p.RefPatterns, p.RootThreshold); err != nil {
		return nil, err
	}

	return targetsMetadata, nil
}

// authorizedRSLSigners returns the principal IDs authorized by the top-level
// targets rule file.
func authorizedRSLSigners(state *policy.State) ([]string, error) {
	if !state.HasTargetsRole(policy.TargetsRoleName) {
		return nil, nil
	}

	targetsMetadata, err := state.GetTargetsMetadata(policy.TargetsRoleName, false)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var signers []string
	for _, rule := range targetsMetadata.GetRules() {
		principalIDs := rule.GetPrincipalIDs()
		if principalIDs == nil {
			continue
		}
		for _, id := range principalIDs.Contents() {
			if seen[id] {
				continue
			}
			seen[id] = true
			signers = append(signers, id)
		}
	}

	return signers, nil
}

// principalsFromPublicKeys builds gittuf principals for a set of raw ed25519
// public keys.
func principalsFromPublicKeys(pubs []ed25519.PublicKey) ([]tuf.Principal, error) {
	principals := make([]tuf.Principal, 0, len(pubs))
	for _, pub := range pubs {
		principal, err := newED25519Principal(pub)
		if err != nil {
			return nil, err
		}
		principals = append(principals, principal)
	}
	return principals, nil
}

func principalIDs(principals []tuf.Principal) []string {
	ids := make([]string, 0, len(principals))
	for _, principal := range principals {
		ids = append(ids, principal.ID())
	}
	return ids
}

// sshSLibKey builds an SSH-type SSLibKey for the given SSH public key. This
// mirrors the internal ssh.newSSHKey helper, which is unexported. The KeyID is
// the SHA-256 SSH fingerprint.
func sshSLibKey(pub ssh.PublicKey) *signerverifier.SSLibKey {
	return &signerverifier.SSLibKey{
		KeyID:   ssh.FingerprintSHA256(pub),
		KeyType: "ssh",
		Scheme:  pub.Type(),
		KeyVal:  signerverifier.KeyVal{Public: base64.StdEncoding.EncodeToString(pub.Marshal())},
	}
}

func isReferenceNotFound(err error) bool {
	return errors.Is(err, gitstore.ErrReferenceNotFound)
}
