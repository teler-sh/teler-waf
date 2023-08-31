// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package dsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunDSL(t *testing.T) {
	env := New()

	program, err := env.Compile("1+1")
	assert.ErrorIs(t, err, nil)

	env.Requests = make(map[string]any)

	res, err := env.Run(program)
	assert.ErrorIs(t, err, nil)

	assert.Equal(t, 2, res)
}
