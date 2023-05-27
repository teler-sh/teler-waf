package request

var methodMap = map[string]Method{
	"GET":     GET,
	"HEAD":    HEAD,
	"POST":    POST,
	"PUT":     PUT,
	"PATCH":   PATCH,
	"DELETE":  DELETE,
	"CONNECT": CONNECT,
	"OPTIONS": OPTIONS,
	"TRACE":   TRACE,
	"ALL":     ALL,
}

var elementMap = map[string]Element{
	"uri":     URI,
	"URI":     URI,
	"headers": Headers,
	"Headers": Headers,
	"HEADERS": Headers,
	"body":    Body,
	"Body":    Body,
	"BODY":    Body,
	"any":     Any,
	"Any":     Any,
	"ANY":     Any,
}
