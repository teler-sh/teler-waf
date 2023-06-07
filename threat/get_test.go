package threat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet(t *testing.T) {
	err := Get()
	assert.Nil(t, err)
}

func TestIsUpdated(t *testing.T) {
	updated, err := IsUpdated()

	assert.Nil(t, err)
	assert.Equal(t, updated, true)
}
