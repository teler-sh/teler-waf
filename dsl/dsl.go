// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

/*
Package dsl provides a Domain Specific Language (DSL) for
defining conditions and evaluating incoming requests.

The DSL provided by this package allows users to define
custom conditions and rules for evaluating incoming requests.
It provides an environment (Env) where the DSL expressions
can be compiled and executed.

This package provides a flexible and extensible DSL for
defining conditions and rules in order to evaluate incoming
requests in a customizable manner.
*/
package dsl

import (
	"strings"

	"github.com/antonmedv/expr"
	"github.com/daniel-hutao/spinlock"
	"github.com/kitabisa/teler-waf/threat"
	"github.com/projectdiscovery/mapcidr"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Env represents the environment for the DSL.
type Env struct {
	// Threat represents a threat category.
	Threat threat.Threat

	// Requests is a map that holds incoming request information.
	Requests map[string]any

	// funcs is a map that associates function names with their respective functions.
	funcs map[string]any

	// vars is a map that associates variable names with their respective values.
	vars map[string]any

	// opts is a slice of Expr config options
	opts []expr.Option

	// sl (SpinLock) is a is a simple spin lock implementation with
	// exponential backoff and adaptive spinning.
	sl spinlock.SpinLock
}

// Env represents the environment for the DSL.
func New() *Env {
	// Create a new Env instance.
	env := &Env{}

	// Initialize vars to a map of variable names and their corresponding values.
	env.vars = map[string]any{
		"request": env.Requests,
		"threat":  env.Threat,
	}

	// Assign each threat category to the funcs map.
	for _, t := range threat.List() {
		env.vars[t.String()] = t
	}

	// Initialize funcs to a map of function names and their corresponding functions.
	env.funcs = map[string]any{
		"cidr":        mapcidr.IPAddresses,
		"clone":       strings.Clone,
		"containsAny": strings.ContainsAny,
		"equalFold":   strings.EqualFold,
		"hasPrefix":   strings.HasPrefix,
		"hasSuffix":   strings.HasSuffix,
		"join":        strings.Join,
		"repeat":      strings.Repeat,
		"replace":     strings.Replace,
		"replaceAll":  strings.ReplaceAll,
		"title":       cases.Title(language.Und).String,
		"toLower":     strings.ToLower,
		"toTitle":     strings.ToTitle,
		"toUpper":     strings.ToUpper,
		"toValidUTF8": strings.ToValidUTF8,
		"trim":        strings.Trim,
		"trimLeft":    strings.TrimLeft,
		"trimPrefix":  strings.TrimPrefix,
		"trimRight":   strings.TrimRight,
		"trimSpace":   strings.TrimSpace,
		"trimSuffix":  strings.TrimSuffix,
	}

	// Define the options for compilation.
	env.opts = []expr.Option{
		expr.Env(env.vars),             // Use the environment's variables.
		expr.Env(env.funcs),            // Use the environment's functions.
		expr.AllowUndefinedVariables(), // Allow the use of undefined variables.
	}

	// Return the initialized Env instance.
	return env
}
