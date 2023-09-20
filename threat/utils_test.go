// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

package threat

import (
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/assert"
)

func TestString(t *testing.T) {
	for k, v := range str {
		t.Run(k.String(), func(t *testing.T) {
			assert.Equal(t, k.String(), v)
		})
	}
}

func TestFilename(t *testing.T) {
	for k, v := range file {
		fn, err := k.Filename(false)

		assert.Nil(t, err)
		assert.Equal(t, fn, v)
	}

	for k, v := range file {
		t.Run(k.String(), func(t *testing.T) {
			fn, err := k.Filename(true)
			assert.Nil(t, err)

			loc, err := Location()
			assert.Nil(t, err)

			assert.Equal(t, fn, filepath.Join(loc, v))
		})
	}
}

func TestList(t *testing.T) {
	list := List()
	assert.LessOrEqual(t, len(list), len(str))
}

func TestCount(t *testing.T) {
	l := List()
	for _, k := range l {
		t.Run(k.String(), func(t *testing.T) {
			i, err := k.Count()
			assert.Nil(t, err)
			assert.Greater(t, i, int(0))
		})
	}
}
