// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package addgroup

import (
	"fmt"

	"github.com/gittuf/gittuf/experimental/gittuf"
	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cmd/trust/persistent"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/spf13/cobra"
)

type options struct {
	p            *persistent.Options
	groupName    string
	principalIDs []string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.groupName,
		"group-name",
		"",
		"name of the group",
	)
	cmd.MarkFlagRequired("group-name") //nolint:errcheck

	cmd.Flags().StringArrayVar(
		&o.principalIDs,
		"member",
		nil,
		"principal ID to include in the group (repeatable)",
	)
	cmd.MarkFlagRequired("member") //nolint:errcheck
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

	return repo.AddGroup(cmd.Context(), signer, o.groupName, o.principalIDs, true, opts...)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "add-group",
		Short:             fmt.Sprintf("Declare a principal group in the root of trust metadata for use in Cedar policies (developer mode only, set %s=1)", dev.DevModeKey),
		Long:              fmt.Sprintf("The 'add-group' command declares a principal group in the root of trust metadata. Groups can be referenced in Cedar policies to apply rules to a set of principals collectively. (developer mode only, set %s=1)", dev.DevModeKey),
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
