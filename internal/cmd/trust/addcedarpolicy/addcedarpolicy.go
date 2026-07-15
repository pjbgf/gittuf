// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package addcedarpolicy

import (
	"fmt"
	"os"

	"github.com/gittuf/gittuf/experimental/gittuf"
	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cmd/trust/persistent"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/spf13/cobra"
)

type options struct {
	p          *persistent.Options
	filePath   string
	policyName string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&o.policyName,
		"policy-name",
		"n",
		"",
		"name of the cedar policy",
	)
	cmd.MarkFlagRequired("policy-name") //nolint:errcheck

	cmd.Flags().StringVarP(
		&o.filePath,
		"file-path",
		"f",
		"",
		"path to the cedar policy file",
	)
	cmd.MarkFlagRequired("file-path") //nolint:errcheck
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	if !dev.InDevMode() {
		return dev.ErrNotInDevMode
	}

	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

	policyBytes, err := os.ReadFile(o.filePath)
	if err != nil {
		return err
	}

	opts := []trustpolicyopts.Option{}
	if o.p.WithRSLEntry {
		opts = append(opts, trustpolicyopts.WithRSLEntry())
	}

	return repo.AddCedarPolicy(cmd.Context(), signer, o.policyName, policyBytes, true, opts...)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "add-cedar-policy",
		Short:             fmt.Sprintf("Declare a Cedar policy file in the root of trust metadata (developer mode only, set %s=1)", dev.DevModeKey),
		Long:              fmt.Sprintf("The 'add-cedar-policy' command declares a Cedar policy file in the root of trust metadata. During verification it acts as a forbid-only veto — a change gittuf's rules permit is rejected only when an explicit forbid statement matches. (developer mode only, set %s=1)", dev.DevModeKey),
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
