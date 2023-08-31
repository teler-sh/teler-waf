// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

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
