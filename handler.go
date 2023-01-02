package teler

import (
	"fmt"

	"net/http"
)

// defaultHandler is default rejection handler
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	// Set Content-Type to text/html
	w.Header().Set("Content-Type", "text/html")

	// Set the status code to 403
	w.WriteHeader(http.StatusForbidden)

	// Write a response from forbidden template
	fmt.Fprintf(w, forbiddenTpl, w.Header().Get(xTelerReqId)) // nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
}

// SetHandler sets the handler to call when the teler rejects a request.
func (t *Teler) SetHandler(handler http.Handler) {
	t.handler = handler
}

// Handler implements the http.HandlerFunc for integration with the standard net/http library.
func (t *Teler) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let teler analyze the request. If it returns an error,
		// that indicates the request should not continue.
		k, err := t.analyzeRequest(w, r)
		if err != nil {
			// Process the analyzeRequest
			t.postAnalyze(w, r, k, err)

			return
		}

		h.ServeHTTP(w, r)
	})
}

// HandlerFuncWithNext is a special implementation for Negroni, but could be used elsewhere.
func (t *Teler) HandlerFuncWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Let teler analyze the request. If it returns an error,
	// that indicates the request should not continue.
	k, err := t.analyzeRequest(w, r)
	if err != nil {
		// Process the analyzeRequest
		t.postAnalyze(w, r, k, err)

		return
	}

	// If next handler is not nil, call it.
	if next != nil {
		next(w, r)
	}
}
