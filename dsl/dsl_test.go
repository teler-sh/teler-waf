package dsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDSL(t *testing.T) {
	env := new(Env)
	expectedEnv := New()

	assert.NotEqual(t, env, expectedEnv)
}
