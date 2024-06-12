package main

import (
    "github.com/teler-sh/teler-waf"

    "gofr.dev/pkg/gofr"
)

func main() {
    app := gofr.New()

    app.GET("/", func(ctx *gofr.Context) (interface{}, error) {
        return "Hello, world!", nil
    })

    telerMiddleware := teler.New()
    app.UseMiddleware(telerMiddleware.Handler)

    app.Run()
}
