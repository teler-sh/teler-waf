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
