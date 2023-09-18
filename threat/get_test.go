// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

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
