// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

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
