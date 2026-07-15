// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package removecedarpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/internal/cmd"
	"github.com/gittuf/gittuf/internal/cmd/trust/persistent"
	"github.com/gittuf/gittuf/internal/dev"
	artifacts "github.com/gittuf/gittuf/internal/testartifacts"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/stretchr/testify/assert"
)

const testCedarPolicy = `forbid (
  principal,
  action == Gittuf::Action::"create",
  resource is Gittuf::GitRef
) when { resource.path like "refs/tags/*" };`

func TestRemoveCedarPolicy(t *testing.T) {
	t.Run("not in dev mode", func(t *testing.T) {
		pOpts := &persistent.Options{}
		_, _, _, err := cmd.ExecuteCommandC(New(pOpts), "--policy-name", "test-policy")
		assert.ErrorIs(t, err, dev.ErrNotInDevMode)
	})

	t.Run("no repository", func(t *testing.T) {
		t.Setenv(dev.DevModeKey, "1")

		tmpDir := t.TempDir()

		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Chdir(cwd)
		}()

		if err := os.Chdir(tmpDir); err != nil {
			t.Fatal(err)
		}

		pOpts := &persistent.Options{
			SigningKey: "dummy-key",
		}

		_, _, _, err = cmd.ExecuteCommandC(New(pOpts), "--policy-name", "test-policy")
		assert.ErrorContains(t, err, "unable to identify git directory")
	})

	t.Run("invalid signer", func(t *testing.T) {
		t.Setenv(dev.DevModeKey, "1")

		tmpDir := t.TempDir()
		gitinterface.CreateTestGitRepository(t, tmpDir, false)

		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Chdir(cwd)
		}()

		if err := os.Chdir(tmpDir); err != nil {
			t.Fatal(err)
		}

		pOpts := &persistent.Options{
			SigningKey: "non-existent-key",
		}

		_, _, _, err = cmd.ExecuteCommandC(New(pOpts), "--policy-name", "test-policy")
		assert.ErrorContains(t, err, "failed to run command")
	})

	t.Run("success", func(t *testing.T) {
		t.Setenv(dev.DevModeKey, "1")

		tmpDir := t.TempDir()
		gitinterface.CreateTestGitRepository(t, tmpDir, false)

		keyPath := filepath.Join(tmpDir, "test-key")
		if err := os.WriteFile(keyPath, artifacts.SSHED25519Private, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath+".pub", artifacts.SSHED25519PublicSSH, 0o600); err != nil {
			t.Fatal(err)
		}

		policyPath := filepath.Join(tmpDir, "policy.cedar")
		if err := os.WriteFile(policyPath, []byte(testCedarPolicy), 0o600); err != nil {
			t.Fatal(err)
		}

		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Chdir(cwd)
		}()

		if err := os.Chdir(tmpDir); err != nil {
			t.Fatal(err)
		}

		repo, err := gittuf.LoadRepository(".")
		if err != nil {
			t.Fatal(err)
		}

		signer, err := gittuf.LoadSigner(repo, keyPath)
		if err != nil {
			t.Fatal(err)
		}

		if err := repo.InitializeRoot(t.Context(), signer, false); err != nil {
			t.Fatal(err)
		}

		if err := repo.AddCedarPolicy(t.Context(), signer, "test-policy", []byte(testCedarPolicy), false); err != nil {
			t.Fatal(err)
		}

		pOpts := &persistent.Options{
			SigningKey: keyPath,
		}

		_, _, _, err = cmd.ExecuteCommandC(New(pOpts), "--policy-name", "test-policy")
		assert.NoError(t, err)
	})

	t.Run("success with RSL entry", func(t *testing.T) {
		t.Setenv(dev.DevModeKey, "1")

		tmpDir := t.TempDir()
		gitinterface.CreateTestGitRepository(t, tmpDir, false)

		keyPath := filepath.Join(tmpDir, "test-key")
		if err := os.WriteFile(keyPath, artifacts.SSHED25519Private, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath+".pub", artifacts.SSHED25519PublicSSH, 0o600); err != nil {
			t.Fatal(err)
		}

		policyPath := filepath.Join(tmpDir, "policy.cedar")
		if err := os.WriteFile(policyPath, []byte(testCedarPolicy), 0o600); err != nil {
			t.Fatal(err)
		}

		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Chdir(cwd)
		}()

		if err := os.Chdir(tmpDir); err != nil {
			t.Fatal(err)
		}

		repo, err := gittuf.LoadRepository(".")
		if err != nil {
			t.Fatal(err)
		}

		signer, err := gittuf.LoadSigner(repo, keyPath)
		if err != nil {
			t.Fatal(err)
		}

		if err := repo.InitializeRoot(t.Context(), signer, false); err != nil {
			t.Fatal(err)
		}

		if err := repo.AddCedarPolicy(t.Context(), signer, "test-policy", []byte(testCedarPolicy), false); err != nil {
			t.Fatal(err)
		}

		pOpts := &persistent.Options{
			SigningKey:   keyPath,
			WithRSLEntry: true,
		}

		_, _, _, err = cmd.ExecuteCommandC(New(pOpts), "--policy-name", "test-policy")
		assert.NoError(t, err)
	})
}
