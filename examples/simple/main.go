package main

import (
	"net/http"

	"github.com/kitabisa/teler-waf"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello world"))
})

func main() {
	telerMiddleware := teler.New()

	app := telerMiddleware.Handler(myHandler)
	http.ListenAndServe("127.0.0.1:3000", app)
}
