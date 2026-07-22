// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package cedar

import (
	"fmt"
	"testing"
)

// syntheticPolicy returns a Cedar forbid statement that matches a ref path that
// is never pushed in bench scenarios, so Veto always returns no violations.
func syntheticPolicy(i int) []byte {
	return []byte(fmt.Sprintf(`forbid (
  principal,
  action,
  resource is Gittuf::GitRef
) when { resource.path == "refs/heads/never-%d" };`, i))
}

func BenchmarkAddPolicies(b *testing.B) {
	for _, n := range []int{1, 5, 10, 100, 300} {
		sources := make([][]byte, n)
		for i := range n {
			sources[i] = syntheticPolicy(i)
		}

		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				ps := NewPolicySet()
				for i, src := range sources {
					if err := ps.AddPolicies(fmt.Sprintf("bench-%d", i), src); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkVeto(b *testing.B) {
	op := Operation{Action: ActionUpdate, ResourcePath: "refs/heads/main"}

	for _, n := range []int{1, 5, 10, 100, 300} {
		sources := make([][]byte, n)
		for i := range n {
			sources[i] = syntheticPolicy(i)
		}

		ps := NewPolicySet()
		for i, src := range sources {
			if err := ps.AddPolicies(fmt.Sprintf("bench-%d", i), src); err != nil {
				b.Fatal(err)
			}
		}
		entities := BuildEntities([]string{"alice"}, nil, []Operation{op})

		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_ = ps.Veto("alice", entities, []Operation{op})
			}
		})
	}
}
