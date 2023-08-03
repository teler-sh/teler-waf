package dsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRequestValue(t *testing.T) {
	clientIP := "127.0.0.1"

	env := New()
	env.Requests = map[string]any{"IP": clientIP}

	get := env.GetRequestValue("IP")

	assert.Equal(t, get, clientIP)
}
