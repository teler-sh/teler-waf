package main

import "net/http"

var static = http.FileServer(http.Dir("static"))
