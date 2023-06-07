package threat

import (
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/assert"
)

func TestString(t *testing.T) {
	for k, v := range str {
		assert.Equal(t, k.String(), v)
	}
}

func TestFilename(t *testing.T) {
	for k, v := range file {
		fn, err := k.Filename(false)

		assert.Nil(t, err)
		assert.Equal(t, fn, v)
	}

	for k, v := range file {
		fn, err := k.Filename(true)
		assert.Nil(t, err)

		loc, err := location()
		assert.Nil(t, err)

		assert.Equal(t, fn, filepath.Join(loc, v))
	}
}

func TestList(t *testing.T) {
	list := List()
	assert.LessOrEqual(t, len(list), len(str))
}
