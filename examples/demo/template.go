package main

import "text/template"

var index = template.Must(template.ParseFiles("index.html"))
var ouch = template.Must(template.ParseFiles("403.txt"))
