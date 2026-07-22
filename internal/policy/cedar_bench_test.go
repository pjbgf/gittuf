// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"testing"

	"github.com/gittuf/gittuf/internal/common"
	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	"github.com/gittuf/gittuf/internal/signerverifier/gpg"
	tufv01 "github.com/gittuf/gittuf/internal/tuf/v01"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
)

// syntheticBenchPolicy returns a Cedar forbid statement matching a ref path
// that is never pushed, so Veto always returns no violations.
func syntheticBenchPolicy(i int) string {
	return fmt.Sprintf(`forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { resource.path == "refs/heads/never-%d" };`, i)
}

// benchStateWithPolicy builds a policy State equivalent to createTestStateWithPolicy
// but accepts testing.TB so it can be called from benchmarks.
func benchStateWithPolicy(b testing.TB) *State {
	b.Helper()

	signer := setupSSHKeysForSigning(b, rootKeyBytes, rootPubKeyBytes)
	key := tufv01.NewKeyFromSSLibKey(signer.MetadataKey())

	rootMetadata, err := InitializeRootMetadata(key)
	if err != nil {
		b.Fatal(err)
	}
	if err := rootMetadata.AddPrimaryRuleFilePrincipal(key); err != nil {
		b.Fatal(err)
	}

	rootEnv, err := dsse.CreateEnvelope(rootMetadata)
	if err != nil {
		b.Fatal(err)
	}
	rootEnv, err = dsse.SignEnvelope(context.Background(), rootEnv, signer)
	if err != nil {
		b.Fatal(err)
	}

	gpgKeyR, err := gpg.LoadGPGKeyFromBytes(gpgPubKeyBytes)
	if err != nil {
		b.Fatal(err)
	}
	gpgKey := tufv01.NewKeyFromSSLibKey(gpgKeyR)

	targetsMetadata := InitializeTargetsMetadata()
	if err := targetsMetadata.AddPrincipal(gpgKey); err != nil {
		b.Fatal(err)
	}
	if err := targetsMetadata.AddRule("protect-main", []string{gpgKey.KeyID}, []string{"git:refs/heads/main"}, 1); err != nil {
		b.Fatal(err)
	}
	if err := targetsMetadata.AddRule("protect-files-1-and-2", []string{gpgKey.KeyID}, []string{"file:1", "file:2"}, 1); err != nil {
		b.Fatal(err)
	}

	targetsEnv, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		b.Fatal(err)
	}
	targetsEnv, err = dsse.SignEnvelope(context.Background(), targetsEnv, signer)
	if err != nil {
		b.Fatal(err)
	}

	state := &State{
		Metadata: &StateMetadata{
			RootEnvelope:    rootEnv,
			TargetsEnvelope: targetsEnv,
		},
	}
	if err := state.preprocess(); err != nil {
		b.Fatal(err)
	}
	return state
}

// createBenchRepositoryWithCedarPolicies mirrors createTestRepositoryWithCedarPolicy
// but adds n synthetic Cedar policy blobs (none matching any pushed ref) so
// applyCedarVeto never vetoes, and refs branches each carrying one commit and
// one RSL entry — modelling a push that changes refs references. For n=0, no
// cedar policies are added.
func createBenchRepositoryWithCedarPolicies(b *testing.B, n, refs int) (*gitinterface.Repository, *State, []*rsl.ReferenceEntry) {
	b.Helper()

	state := benchStateWithPolicy(b)

	tempDir := b.TempDir()
	repo := gitinterface.CreateTestGitRepository(b, tempDir, false)
	state.repository = repo

	if n > 0 {
		rootMetadata, err := state.GetRootMetadata(false)
		if err != nil {
			b.Fatal(err)
		}

		for i := range n {
			src := []byte(syntheticBenchPolicy(i))
			blobID, err := repo.WriteBlob(src)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := rootMetadata.AddCedarPolicy(fmt.Sprintf("bench-%d", i), map[string]string{gitinterface.GitBlobHashName: blobID.String()}); err != nil {
				b.Fatal(err)
			}
		}

		signer := setupSSHKeysForSigning(b, rootKeyBytes, rootPubKeyBytes)
		rootEnv, err := dsse.CreateEnvelope(rootMetadata)
		if err != nil {
			b.Fatal(err)
		}
		rootEnv, err = dsse.SignEnvelope(testCtx, rootEnv, signer)
		if err != nil {
			b.Fatal(err)
		}
		state.Metadata.RootEnvelope = rootEnv

		if err := state.preprocess(); err != nil {
			b.Fatal(err)
		}
	}

	if err := state.Commit(repo, "bench state", true, false); err != nil {
		b.Fatal(err)
	}
	if err := Apply(testCtx, repo, false); err != nil {
		b.Fatal(err)
	}

	latestEntry, err := rsl.GetLatestEntry(repo)
	if err != nil {
		b.Fatal(err)
	}
	state.loadedEntry = latestEntry.(rsl.ReferenceUpdaterEntry)

	entries := make([]*rsl.ReferenceEntry, 0, refs)
	for i := range refs {
		refName := fmt.Sprintf("refs/heads/branch-%d", i)
		commitIDs := common.AddNTestCommitsToSpecifiedRef(b, repo, refName, 1, gpgKeyBytes)
		entry := rsl.NewReferenceEntry(refName, commitIDs[0])
		entry.ID = common.CreateTestRSLReferenceEntryCommit(b, repo, entry, gpgKeyBytes)
		entries = append(entries, entry)
	}

	return repo, state, entries
}

func BenchmarkApplyCedarVeto(b *testing.B) {
	for _, n := range []int{1, 5, 10, 100, 300} {
		for _, refs := range []int{1, 5, 100} {
			b.Run(fmt.Sprintf("policies=%d/refs=%d", n, refs), func(b *testing.B) {
				repo, state, entries := createBenchRepositoryWithCedarPolicies(b, n, refs)

				b.ResetTimer()
				b.ReportAllocs()
				for range b.N {
					for _, entry := range entries {
						if err := applyCedarVeto(testCtx, repo, state, entry); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
