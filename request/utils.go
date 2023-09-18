// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

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
