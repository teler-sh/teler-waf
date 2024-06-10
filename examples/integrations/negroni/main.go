package main

import (
	"net/http"

	"github.com/teler-sh/teler-waf"
	"github.com/urfave/negroni"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello world"))
	})

	telerMiddleware := teler.New()

	// Note this implementation has a special helper function called HandlerFuncWithNext.
	n := negroni.Classic()
	n.Use(negroni.HandlerFunc(telerMiddleware.HandlerFuncWithNext))
	n.UseHandler(mux)

	n.Run("127.0.0.1:3000")
}
