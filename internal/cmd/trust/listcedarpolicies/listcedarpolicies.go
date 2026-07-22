// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package listcedarpolicies

import (
	"fmt"

	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/spf13/cobra"
)

const indentString = "    "

type options struct {
	targetRef string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.targetRef,
		"target-ref",
		"policy",
		"specify which policy ref should be inspected",
	)
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	policies, err := repo.ListCedarPolicies(cmd.Context(), o.targetRef)
	if err != nil {
		return err
	}

	stdOut := cmd.OutOrStdout()

	for _, policy := range policies {
		fmt.Fprintf(stdOut, "Cedar policy '%s':\n", policy.ID())
		for algo, hash := range policy.GetHashes() {
			fmt.Fprintf(stdOut, "%s%s: %s\n", indentString, algo, hash)
		}
	}

	return nil
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:               "list-cedar-policies",
		Short:             "List Cedar policies declared in the current policy state",
		Long:              "The 'list-cedar-policies' command displays the configured Cedar policies declared in the root of trust metadata for the current policy state.",
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
