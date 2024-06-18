// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/valyala/fasttemplate"
)

// rejectHandler is default rejection handler
func rejectHandler(w http.ResponseWriter, r *http.Request) {
	// Set Content-Type to text/html
	w.Header().Set("Content-Type", "text/html")

	// Set the status code
	w.WriteHeader(respStatus)

	// Set template interfaces
	data := map[string]any{
		// NOTE(dwisiswant0): Should we include *http.Request?
		"ID":      w.Header().Get(xTelerReqId),
		"message": w.Header().Get(xTelerMsg),
		"threat":  w.Header().Get(xTelerThreat),
	}

	// Use custom response HTML page template if non-empty
	if customHTMLResponse != "" {
		respTemplate = customHTMLResponse
	}

	// Parse response template
	tpl := fasttemplate.New(respTemplate, "{{", "}}")

	// Write a response from the template
	// TODO(dwisiswant0): Add error handling here.
	_, _ = tpl.Execute(w, data)
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

// CaddyHandler is a special HTTP handler implementation for Caddy.
func (t *Teler) CaddyHandler(h caddyhttp.Handler) caddyhttp.HandlerFunc {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Let teler analyze the request. If it returns an error,
		// that indicates the request should not continue.
		k, err := t.analyzeRequest(w, r)
		if err != nil {
			// Process the analyzeRequest
			t.postAnalyze(w, r, k, err)

			return err
		}

		return h.ServeHTTP(w, r)
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

// CaddyHandlerFuncWithNext is a special implementation for Caddy.
func (t *Teler) CaddyHandlerFuncWithNext(w http.ResponseWriter, r *http.Request, next caddyhttp.HandlerFunc) error {
	// Let teler analyze the request. If it returns an error,
	// that indicates the request should not continue.
	k, err := t.analyzeRequest(w, r)
	if err != nil {
		// Process the analyzeRequest
		t.postAnalyze(w, r, k, err)

		return err
	}

	// If next handler is not nil, call it.
	if next != nil {
		return next(w, r)
	}

	return nil
}
