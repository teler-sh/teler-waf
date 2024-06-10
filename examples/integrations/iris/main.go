package main

import (
	"github.com/kataras/iris/v12"
	"github.com/teler-sh/teler-waf"
)

func main() {
	app := iris.New()

	telerMiddleware := teler.New()

	app.Use(iris.FromStd(telerMiddleware.HandlerFuncWithNext))
	// Identical to:
	// app.Use(func(ctx iris.Context) {
	//     err := telerMiddleware.Process(ctx.ResponseWriter(), ctx.Request())
	//
	//     // If there was an error, do not continue.
	//     if err != nil {
	//         return
	//     }
	//
	//     ctx.Next()
	// })

	app.Get("/home", func(ctx iris.Context) {
		ctx.Writef("hello world, %+v", ctx)
	})

	app.Listen(":8080")
}
