// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToMethod(t *testing.T) {
	for k, v := range methodMap {
		assert.Equal(t, ToMethod(k), v)
	}

	assert.Equal(t, ToMethod("foo"), Method(""))
}

func TestToElement(t *testing.T) {
	for k, v := range elementMap {
		assert.Equal(t, ToElement(k), v)
	}

	assert.Equal(t, ToElement("foo"), Element(-1))
}
