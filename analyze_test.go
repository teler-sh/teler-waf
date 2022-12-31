package teler

import (
	"testing"

	"net/http/httptest"
)

func TestAnalyze(t *testing.T) {
	// Create a mock Teler
	teler := New()

	// Create a mock HTTP request using the httptest package
	r := httptest.NewRequest("GET", "/", nil)

	// Create a mock HTTP response using the httptest package
	w := httptest.NewRecorder()

	// Call the Analyze function with the mock request and response
	err := teler.Analyze(w, r)
	if err != nil {
		t.Fatal(err)
	}
}
