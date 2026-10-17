package app

import (
	"fmt"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// validateChainGraph checks the goto/jump chain graph the loader built,
// so that traversal can never loop at runtime (PLAN §8): chain names are
// unique (goto/jump name their targets by name), every goto/jump target
// names an existing chain, and the graph is acyclic — a DAG, so shared
// target chains are allowed.
func validateChainGraph(chains []bandage.Chain) error {
	index := make(map[string]int, len(chains))
	for i, chain := range chains {
		if _, dup := index[chain.Name]; dup {
			return fmt.Errorf("rules: duplicate chain name %q", chain.Name)
		}
		index[chain.Name] = i
	}

	// edges[i] are the chain indices chain i's goto/jump actions target.
	edges := make([][]int, len(chains))
	for i := range chains {
		for _, rule := range chains[i].Rules {
			for _, action := range rule.Actions {
				name, target := "jump", action.Jump
				if action.Goto != "" {
					name, target = "goto", action.Goto
				}
				if target == "" {
					continue
				}
				j, ok := index[target]
				if !ok {
					return fmt.Errorf("rules: rule %q: %s targets nonexistent chain %q", rule.ID, name, target)
				}
				edges[i] = append(edges[i], j)
			}
		}
	}

	// Depth-first cycle detection: 0 = unvisited, 1 = on the visit
	// stack, 2 = done. A back edge to a chain on the stack is a cycle.
	const (
		unvisited = 0
		onStack   = 1
		done      = 2
	)
	state := make([]uint8, len(chains))
	var visit func(i int) error
	visit = func(i int) error {
		switch state[i] {
		case onStack:
			return fmt.Errorf("rules: goto/jump graph has a cycle through chain %q", chains[i].Name)
		case done:
			return nil
		}
		state[i] = onStack
		for _, j := range edges[i] {
			if err := visit(j); err != nil {
				return err
			}
		}
		state[i] = done
		return nil
	}
	for i := range chains {
		if err := visit(i); err != nil {
			return err
		}
	}
	return nil
}
