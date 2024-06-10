package main

import (
	"net/http"

	"github.com/arl/statsviz"
	"github.com/teler-sh/teler-waf"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello world"))
}

func main() {
	telerMiddleware := teler.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/", helloHandler)

	if err := statsviz.Register(mux); err != nil {
		panic(err)
	}

	app := telerMiddleware.Handler(mux)
	http.ListenAndServe("127.0.0.1:3000", app)
}
