package teler

import (
	"testing"

	"net/http"
	"net/http/httptest"

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
