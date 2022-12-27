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
	fmt.Fprintf(w, forbiddenTpl, w.Header().Get(xTelerReqId))
}

// SetHandler sets the handler to call when the teler rejects a request.
func (t *Teler) SetHandler(handler http.Handler) {
	t.handler = handler
}
