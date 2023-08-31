// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package dsl

import (
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
)

/*
Compile will compiles the given code string into a [vm.Program].

The code string contains DSL (Domain Specific Language) expressions
that can be used to define conditions for evaluating incoming requests.
Here are some examples of DSL expression code:

# Examples of DSL expression code:

Check if the incoming request headers contains "curl":

	request.Headers contains "curl"

Check if the incoming request method is "GET":

	request.Method == "GET"

Check if the incoming request method is "GET" or "POST"
using regular expression [operator] matching:

	request.Method matches "^(POS|GE)T$"

Check if the incoming request IP address is from localhost:

	request.IP in ["127.0.0.1", "::1", "0.0.0.0"]

Check if the any element in request contains the string "foo":

	one(request.ALL, # contains "foo")

Check if the incoming request body contains "foo":

	request.Body contains "foo"

Check whether the current threat category being analyzed
is [threat.BadCrawler] or [threat.DirectoryBruteforce]:

	threat in [BadCrawler, DirectoryBruteforce]

# Available variables:

# Threat category

All constant identifiers of the [threat.Threat] type are valid variables.

# request

	request

Represents the incoming request fields (URI, Headers, Body, etc.) and its values.

	request.URI

Represents the incoming request URI (path, queries, parameters, and a fragments).

	request.Headers

Represents the incoming request headers in multiple lines.

	request.Body

Represents the incoming request body.

	request.Method

Represents the incoming request method.

	request.IP

Represents the client IP address of the incoming request.

	request.ALL

Represents all the string values from the request fields above in slice.

# threat

	threat

Represents the threat category being analyzed (type of [threat.Threat]).

# Available functions:

The functions available in this package include both
[built-in functions from the expr package] and those
specifically defined for this package. The following
is a list of the functions provided by, which utilize
the functionalities offered by the [strings] package.

  - cidr
  - clone
  - containsAny
  - equalFold
  - hasPrefix
  - hasSuffix
  - join
  - repeat
  - replace
  - replaceAll
  - request
  - threat
  - title
  - toLower
  - toTitle
  - toUpper
  - toValidUTF8
  - trim
  - trimLeft
  - trimPrefix
  - trimRight
  - trimSpace
  - trimSuffix

For more information on operators and built-in functions, please refer to
the [operator] and [built-in functions from the expr package] documentation.

[operator]: https://expr.medv.io/docs/Language-Definition#operators
[built-in functions from the expr package]: https://expr.medv.io/docs/Language-Definition#built-in-functions
*/
func (e *Env) Compile(code string) (*vm.Program, error) {
	// Compile the code into a program using the defined options.
	program, err := expr.Compile(code, e.opts...)
	if err != nil {
		return nil, err
	}

	// Return the compiled program.
	return program, nil
}
