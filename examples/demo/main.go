package main

import (
	"net"
	"os"

	"net/http"

	"github.com/teler-sh/teler-waf"
	"gitlab.com/golang-commonmark/mdurl"
)

type Data struct {
	Query string
	Body  string
	ReqId string
}

func myHandler(w http.ResponseWriter, r *http.Request) {
	data := Data{Query: mdurl.Decode(r.URL.RawQuery), Body: r.FormValue("body")}
	index.Execute(w, data)
}

var forbidden = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	data := Data{ReqId: w.Header().Get("X-Teler-Req-Id")}
	ouch.Execute(w, data)
})

var port string = "3000"

func init() {
	portEnv := os.Getenv("PORT")
	if portEnv != "" {
		port = portEnv
	}
}

func main() {
	waf := teler.New()
	app := waf.Handler(http.HandlerFunc(myHandler))

	http.Handle("/static/", http.StripPrefix("/static/", static))
	http.Handle("/", app)
	http.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	waf.SetHandler(forbidden)

	go func() {
		println("Listening on " + port)
	}()

	http.ListenAndServe(net.JoinHostPort("0.0.0.0", port), nil)
}
