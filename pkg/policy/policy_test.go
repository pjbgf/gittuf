// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gittuf/gittuf/internal/common"
	ipolicy "github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testRepoID      = "entire.io/repo/abc123"
	testRefPattern  = "git:refs/*"
	testRef         = "refs/heads/main"
	customFieldName = "custom.entire.io/repository"
)

// newTestED25519 returns a fresh ed25519 key pair for tests.
func newTestED25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// opensshPEM serializes a raw ed25519 private key into OpenSSH PEM bytes that
// gitinterface.CommitUsingSpecificKey understands.
func opensshPEM(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func newTestRepo(t *testing.T) *gitinterface.Repository {
	t.Helper()
	return gitinterface.CreateTestGitRepository(t, t.TempDir(), false)
}

func bootstrapForTest(t *testing.T, store *gitinterface.Repository) (BootstrapParams, ed25519.PrivateKey, tuf.Principal) {
	t.Helper()

	rootPub, rootPriv := newTestED25519(t)
	rslPub, rslPriv := newTestED25519(t)

	rslPrincipal, err := newED25519Principal(rslPub)
	require.NoError(t, err)

	params := BootstrapParams{
		RepoID:              testRepoID,
		RootPrivateKey:      rootPriv,
		RootPublicKeys:      []ed25519.PublicKey{rootPub},
		RootThreshold:       1,
		RSLSignerPublicKeys: []ed25519.PublicKey{rslPub},
		RefPatterns:         []string{testRefPattern},
		Expires:             time.Now().Add(365 * 24 * time.Hour),
	}

	_, err = Bootstrap(context.Background(), store, params)
	require.NoError(t, err)

	return params, rslPriv, rslPrincipal
}

func TestNewED25519SignerAndPrincipal(t *testing.T) {
	t.Parallel()

	pub, priv := newTestED25519(t)

	signer, err := newED25519Signer(priv)
	require.NoError(t, err)

	principal, err := newED25519Principal(pub)
	require.NoError(t, err)

	signerKeyID, err := signer.KeyID()
	require.NoError(t, err)

	assert.Equal(t, principal.ID(), signerKeyID, "signer KeyID must match principal ID")
	require.Len(t, principal.Keys(), 1)
	assert.Equal(t, "ssh", principal.Keys()[0].KeyType)

	// The signer must actually be usable: sign and verify a payload without
	// any temp files.
	sig, err := signer.Sign(context.Background(), []byte("hello"))
	require.NoError(t, err)
	require.NoError(t, signer.Verify(context.Background(), []byte("hello"), sig))
}

func TestBootstrapAndVerifyRef(t *testing.T) {
	t.Parallel()

	store := newTestRepo(t)
	_, rslPriv, _ := bootstrapForTest(t, store)

	commitIDs := common.AddNTestCommitsToSpecifiedRef(t, store, testRef, 1, opensshPEM(t, rslPriv))

	entry := rsl.NewReferenceEntry(testRef, commitIDs[0])
	if err := entry.CommitUsingSpecificKey(store, opensshPEM(t, rslPriv)); err != nil {
		t.Fatal(err)
	}

	require.NoError(t, VerifyRef(context.Background(), store, testRef))
}

func TestVerifyRefRejectsUnauthorizedSigner(t *testing.T) {
	t.Parallel()

	store := newTestRepo(t)
	_, rslPriv, _ := bootstrapForTest(t, store)

	commitIDs := common.AddNTestCommitsToSpecifiedRef(t, store, testRef, 1, opensshPEM(t, rslPriv))

	// Sign the RSL entry with a key that is NOT authorized.
	_, unauthorizedPriv := newTestED25519(t)
	entry := rsl.NewReferenceEntry(testRef, commitIDs[0])
	if err := entry.CommitUsingSpecificKey(store, opensshPEM(t, unauthorizedPriv)); err != nil {
		t.Fatal(err)
	}

	err := VerifyRef(context.Background(), store, testRef)
	require.Error(t, err)
}

func TestInspectRoot(t *testing.T) {
	t.Parallel()

	store := newTestRepo(t)
	_, _, rslPrincipal := bootstrapForTest(t, store)

	info, err := InspectRoot(context.Background(), store)
	require.NoError(t, err)

	assert.Equal(t, testRepoID, info.RepoID)
	assert.Equal(t, 1, info.Version)
	assert.Contains(t, info.AuthorizedRSLSigners, rslPrincipal.ID())
	assert.NotEmpty(t, info.RootKeyIDs)
}

func TestBootstrapPinsRepoIDIntoRootCustomField(t *testing.T) {
	t.Parallel()

	store := newTestRepo(t)
	bootstrapForTest(t, store)

	state, err := ipolicy.LoadCurrentState(context.Background(), store, ipolicy.PolicyRef)
	require.NoError(t, err)

	rootMetadata, err := state.GetRootMetadata(false)
	require.NoError(t, err)

	fields := rootMetadata.GetCustomFields()
	assert.Equal(t, testRepoID, fields[customFieldName])
}

func TestVerifyRefFromEntry(t *testing.T) {
	t.Parallel()

	store := newTestRepo(t)
	_, rslPriv, _ := bootstrapForTest(t, store)

	commitIDs := common.AddNTestCommitsToSpecifiedRef(t, store, testRef, 1, opensshPEM(t, rslPriv))

	entry := rsl.NewReferenceEntry(testRef, commitIDs[0])
	if err := entry.CommitUsingSpecificKey(store, opensshPEM(t, rslPriv)); err != nil {
		t.Fatal(err)
	}
	entryID, err := store.GetReference(rsl.Ref)
	require.NoError(t, err)

	err = VerifyRefFromEntry(context.Background(), store, testRef, entryID.String())
	require.NoError(t, err)
}
