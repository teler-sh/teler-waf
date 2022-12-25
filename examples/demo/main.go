package main

import (
	"fmt"

	"net/http"

	"github.com/kitabisa/teler-waf"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	form := `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>teler-waf demo</title>
</head>
<body>
<h1>WAF tester</h1>
<p>Put your payload below</p>
<hr>
<h2>GET</h2>
<form method="get">
  <label for="query">query:</label><br>
  <input type="text" id="query" name="query"><br>
  <input type="submit" value="Submit">
</form>
<h2>POST</h2>
<form method="post">
  <label for="body">body:</label><br>
  <input type="text" id="body" name="body"><br>
  <input type="submit" value="Submit">
</form>
<hr>
Your payload writen here:
<p>
  query: %s<br>
  body: %s
</p>
</body>
</html>`

	body := r.FormValue("body")

	// Write the form to the response
	fmt.Fprintf(w, form, r.URL.RawQuery, body)
})

func main() {
	waf := teler.New()
	app := waf.Handler(myHandler)

	http.ListenAndServe("127.0.0.1:3000", app)
}
