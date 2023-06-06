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
