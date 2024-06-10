package main

import (
	"net/http"

	"github.com/teler-sh/teler-waf"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
)

func main() {
	telerMiddleware := teler.New()

	goji.Get("/", func(c web.C, w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hello world"))
	})
	goji.Use(telerMiddleware.Handler)
	goji.Serve() // Defaults to ":8000".
}
