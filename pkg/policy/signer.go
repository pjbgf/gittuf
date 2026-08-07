// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/hiddeco/sshsig"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"golang.org/x/crypto/ssh"
)

// sshSigNamespace matches the namespace gittuf uses for SSH signatures on both
// Git objects and DSSE payloads. It must equal internal/signerverifier/ssh's
// SigNamespace so signatures produced here verify against gittuf's SSH verifier.
const sshSigNamespace = "git"

// sshSignerVerifier is an in-memory dsse.SignerVerifier backed by an SSH signer.
// It produces armored SSH signatures (sshsig, SHA-512, namespace "git") that
// verify against an SSH-type principal, and reports the SSH SHA-256 fingerprint
// as its KeyID. No filesystem access is involved.
type sshSignerVerifier struct {
	signer ssh.Signer
	key    *signerverifier.SSLibKey
}

func newSSHSignerVerifier(signer ssh.Signer, key *signerverifier.SSLibKey) (sslibdsse.SignerVerifier, error) {
	if signer == nil {
		return nil, fmt.Errorf("ssh signer must not be nil")
	}
	if key == nil {
		return nil, fmt.Errorf("ssh key must not be nil")
	}
	return &sshSignerVerifier{signer: signer, key: key}, nil
}

func (s *sshSignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	signature, err := sshsig.Sign(bytes.NewReader(data), s.signer, sshsig.HashSHA512, sshSigNamespace)
	if err != nil {
		return nil, fmt.Errorf("unable to sign using ssh key: %w", err)
	}
	return sshsig.Armor(signature), nil
}

func (s *sshSignerVerifier) Verify(_ context.Context, data, sig []byte) error {
	signature, err := sshsig.Unarmor(sig)
	if err != nil {
		return fmt.Errorf("unable to parse ssh signature: %w", err)
	}
	if err := sshsig.Verify(bytes.NewReader(data), signature, s.signer.PublicKey(), sshsig.HashSHA512, sshSigNamespace); err != nil {
		return fmt.Errorf("unable to verify ssh signature: %w", err)
	}
	return nil
}

func (s *sshSignerVerifier) KeyID() (string, error) {
	return s.key.KeyID, nil
}

func (s *sshSignerVerifier) Public() crypto.PublicKey {
	return s.signer.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey()
}
