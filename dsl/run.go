package dsl

import (
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/kitabisa/teler-waf/threat"
	"github.com/samber/lo"
)

// Run executes the provided expr.Program in the DSL environment.
func (e *Env) Run(program *vm.Program) (any, error) {
	// If the Threat field in the environment is defined, assign it to the "threat" function in the environment.
	if e.Threat != threat.Undefined {
		e.vars["threat"] = e.Threat
	}

	// Initialize the "ALL" field in the Requests map as an empty string slice.
	e.Requests["ALL"] = []string{}

	// Iterate over the values in the Requests map.
	for _, rVal := range e.Requests {
		// Check if the value is a string and not empty.
		if val, ok := rVal.(string); ok && val != "" {
			// Append the value to the "ALL" field in the Requests map.
			e.Requests["ALL"] = append(e.Requests["ALL"].([]string), val)
		}
	}

	// Assign the Requests map to the "request" variable in the environment.
	e.vars["request"] = e.Requests

	// Merge maps of variables and functions
	envMaps := lo.Assign[string, any](e.vars, e.funcs)

	// Run the provided program using the merged environments.
	out, err := expr.Run(program, envMaps)
	if err != nil {
		return nil, err
	}

	// Return the output.
	return out, nil
}
