package main

import (
	"net/http"

	"github.com/teler-sh/teler-waf"
	"github.com/labstack/echo"
)

func main() {
	telerMiddleware := teler.New()

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello world")
	})

	e.Use(echo.WrapMiddleware(telerMiddleware.Handler))
	e.Logger.Fatal(e.Start("127.0.0.1:3000"))
}
