// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

// Rule is custom security rules to apply to incoming requests.
type Rule struct {
	// Name is the name of the rule.
	Name string `json:"name" yaml:"name"`

	// Condition specifies the logical operator to use when evaluating the
	// rule's conditions. Valid values are "and" and "or".
	Condition string `json:"condition" yaml:"condition"`

	// Rules is a list of conditions that must be satisfied for the rule to
	// be triggered. Each condition specifies a request element to match and
	// a pattern to match against the element.
	Rules []Condition `json:"rules" yaml:"rules"`
}
