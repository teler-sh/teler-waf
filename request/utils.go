// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package request

// ToMethod converts a string representation
// of a method to the corresponding Method value.
func ToMethod(s string) Method {
	method, exists := methodMap[s]
	if !exists {
		return UNDEFINED
	}

	return method
}

// ToElement converts a string representation
// of an element to the corresponding Element value.
func ToElement(s string) Element {
	element, exists := elementMap[s]
	if !exists {
		return -1
	}

	return element
}
