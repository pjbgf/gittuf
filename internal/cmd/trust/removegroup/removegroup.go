// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package removegroup

import (
	"fmt"

	"github.com/gittuf/gittuf/experimental/gittuf"
	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cmd/trust/persistent"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/spf13/cobra"
)

type options struct {
	p         *persistent.Options
	groupName string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.groupName,
		"group-name",
		"",
		"name of the group",
	)
	cmd.MarkFlagRequired("group-name") //nolint:errcheck
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

	opts := []trustpolicyopts.Option{}
	if o.p.WithRSLEntry {
		opts = append(opts, trustpolicyopts.WithRSLEntry())
	}

	return repo.RemoveGroup(cmd.Context(), signer, o.groupName, true, opts...)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "remove-group",
		Short:             fmt.Sprintf("Remove a principal group from the root of trust metadata (developer mode only, set %s=1)", dev.DevModeKey),
		Long:              fmt.Sprintf("The 'remove-group' command removes a principal group declared in the root of trust metadata. (developer mode only, set %s=1)", dev.DevModeKey),
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
