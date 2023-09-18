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

	_, err := env.Compile(`1 + 1`)
	assert.ErrorIs(t, err, nil)
}
