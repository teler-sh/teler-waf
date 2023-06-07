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
