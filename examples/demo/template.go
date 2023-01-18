package main

import "text/template"

var index = template.Must(template.ParseFiles(concat("index.html")))
var ouch = template.Must(template.ParseFiles(concat("404.txt")))
