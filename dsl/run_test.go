// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package dsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunDSL(t *testing.T) {
	env := New()

	program, err := env.Compile("1+1")
	assert.ErrorIs(t, err, nil)

	env.Requests = map[string]any{
		"BAR": nil,
		"FOO": "bar",
	}

	res, err := env.Run(program)
	assert.ErrorIs(t, err, nil)

	assert.Equal(t, 2, res)

	t.Run("err", func(t *testing.T) {
		program, err := env.Compile(`"1+10O`)
		assert.NotNil(t, err)

		_, err = env.Run(program)
		assert.NotNil(t, err)
	})
}
