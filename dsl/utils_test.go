// Licensed to Dwi Siswanto under one or more agreements.
// Dwi Siswanto licenses this file to you under the Apache 2.0 License.
// See the LICENSE-APACHE file in the project root for more information.

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
