package main

import (
	"net/http"
	"path/filepath"

	"github.com/kitabisa/teler-waf"
	"gitlab.com/golang-commonmark/mdurl"
)

type Data struct {
	Query string
	Body  string
	ReqId string
}

func concat(path string) string {
	return filepath.Join("examples", "demo", path)
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

func main() {
	waf := teler.New()
	app := waf.Handler(http.HandlerFunc(myHandler))

	http.Handle("/static/", http.StripPrefix("/static/", static))
	http.Handle("/", app)

	waf.SetHandler(forbidden)
	http.ListenAndServe("127.0.0.1:3000", nil)
}
