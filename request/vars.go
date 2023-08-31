// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

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
