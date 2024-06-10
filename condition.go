// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"regexp"

	"github.com/expr-lang/expr/vm"
	"github.com/teler-sh/teler-waf/request"
)

// Condition specifies a request element to match and
// a pattern or DSL expression to match against the element.
type Condition struct {
	// Method is the HTTP method to match against.
	// It is of type request.Method, which is a type alias for string.
	//
	// It will be ignored if DSL is not empty.
	Method request.Method `json:"method" yaml:"method"`

	// Element is the request element to match.
	// These element are defined in the request.Element type.
	//
	// When you specify the definition using JSON or YAML, the value
	// is an `int` that corresponds to the following representations:
	// - `0` represents [request.URI]
	// - `1` represents [request.Headers]
	// - `2` represents [request.Body]
	// - `3` represents [request.Any]
	//
	// It will be ignored if DSL is not empty.
	Element request.Element `json:"element" yaml:"element"`

	// Pattern is the regular expression to match against the element.
	//
	// It will be ignored if DSL is not empty.
	Pattern string `json:"pattern" yaml:"pattern"`

	// patternRegex saves the compiled regular expressions of the
	// Pattern for subsequent use.
	patternRegex *regexp.Regexp

	// DSL is the DSL expression to match against the incoming requests.
	DSL string `json:"dsl" yaml:"dsl"`

	// dslProgram saves the compiled DSL expressions of the code
	// for subsequent use.
	dslProgram *vm.Program
}
