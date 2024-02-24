// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package dsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompileDSL(t *testing.T) {
	env := New()
	expr := `1 + 1`

	_, err := env.Compile(expr)
	assert.ErrorIs(t, err, nil)

	t.Run("err", func(t *testing.T) {
		_, err := env.Compile(expr + "0O")
		assert.NotNil(t, err)
	})
}
