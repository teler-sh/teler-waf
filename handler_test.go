// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
)

type MockHandler struct{}

func (h *MockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add code here to handle the request and write a response
}

func TestSetHandler(t *testing.T) {
	// Create a new Teler struct
	teler := Teler{}

	// Create a mock http.Handler
	mockHandler := &MockHandler{}

	// Call SetHandler with the mock http.Handler
	teler.SetHandler(mockHandler)

	// Assert that the handler field of the Teler struct was set to the mock http.Handler
	assert.Equal(t, teler.handler, mockHandler)
}

func TestHandlerFuncWithNext(t *testing.T) {
	// Create a mock Teler
	teler := New()

	// Create a mock HTTP request using the httptest package
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Initialize next handler
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})

	// Call the HandlerFuncWithNext function with the mock request, response & next
	teler.HandlerFuncWithNext(w, r, next)
}

func TestCaddyHandler(t *testing.T) {
	// Create a mock Teler
	teler := New()

	// Create a mock HTTP request using the httptest package
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Initialize Caddy HTTP handler
	handler := teler.CaddyHandler(caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)

		return nil
	}))

	// Serve
	_ = handler.ServeHTTP(w, r)
}

func TestCaddyHandlerFuncWithNext(t *testing.T) {
	// Create a mock Teler
	teler := New()

	// Create a mock HTTP request using the httptest package
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Initialize Caddy HTTP handler function
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	_ = teler.CaddyHandlerFuncWithNext(w, r, next)
}
