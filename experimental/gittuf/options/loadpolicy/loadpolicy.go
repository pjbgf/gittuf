// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package loadpolicy

import (
	"crypto"

	"github.com/gittuf/gittuf/pkg/githash"
)

type Options struct {
	EntryID         githash.Hash
	AtEntry         bool
	InitialRootKeys []crypto.PublicKey
	BypassRSL       bool
}

type Option func(o *Options)

// WithEntry loads the policy recorded by one RSL policy entry instead of the
// latest one. entryID must name a reference entry for the policy ref that is
// reachable from the RSL.
func WithEntry(entryID githash.Hash) Option {
	return func(o *Options) {
		o.EntryID = entryID
		o.AtEntry = true
	}
}

// WithInitialRootKeys anchors the loaded history to a known first root of trust.
// Without it, the first root in the RSL is trusted on sight.
//
// Every key must have signed the first root. To anchor a root with a threshold
// below its key count, pass only the keys that signed it.
func WithInitialRootKeys(keys ...crypto.PublicKey) Option {
	return func(o *Options) {
		o.InitialRootKeys = keys
	}
}

// WithBypassRSL loads the policy from the commit the policy reference points
// to, not from the RSL. The metadata signatures of that policy are verified.
// The succession of roots that led to it is not. Use it only where every update
// to the policy reference was verified when it was written.
// A policy with controller metadata is refused, because controller metadata is
// verified only for a policy loaded from the RSL.
//
// It cannot be combined with WithEntry or WithInitialRootKeys. Both depend on
// the RSL history that this option skips.
func WithBypassRSL() Option {
	return func(o *Options) {
		o.BypassRSL = true
	}
}
