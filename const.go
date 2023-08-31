// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

const (
	xTelerReqId  = "X-Teler-Req-Id"
	xTelerMsg    = "X-Teler-Msg"
	xTelerThreat = "X-Teler-Threat"

	DefaultStatusResponse = 403
	DefaultHTMLResponse   = `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>403 Forbidden</title>
</head>
<body>
<center>
	<h1>403 Forbidden</h1>
	We're sorry, but your request has been denied for security reasons.<br>
	If you feel this is an error, please contact customer support for further assistance.
</center>
<hr><center>teler rID: {{ID}} <!-- | reason: {{message}} (threat: {{threat}}) --></center>
</body>
</html>
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->`
)

const (
	defaultCondition = "or"
	defaultMethod    = "ALL"
	defaultElement   = "any"
)
