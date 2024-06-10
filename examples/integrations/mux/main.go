package main

import (
	"fmt"
	"log"

	"net/http"

	"github.com/gorilla/mux"
	"github.com/teler-sh/teler-waf"
)

func main() {
	telerMiddleware := teler.New()

	r := mux.NewRouter()
	r.Use(telerMiddleware.Handler)
	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", 8080), nil))
}
