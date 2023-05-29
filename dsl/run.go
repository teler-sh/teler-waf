package dsl

import (
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/kitabisa/teler-waf/threat"
)

// Run executes the provided expr.Program in the DSL environment.
func (e *Env) Run(program *vm.Program) (any, error) {
	// If the Threat field in the environment is defined, assign it to the "threat" function in the environment.
	if e.Threat != threat.Undefined {
		e.funcs["threat"] = e.Threat
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

	// Assign the Requests map to the "request" function in the environment.
	e.funcs["request"] = e.Requests

	// Run the provided program using the environment's functions.
	out, err := expr.Run(program, e.funcs)
	if err != nil {
		return nil, err
	}

	// Return the output.
	return out, nil
}
